// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package trino

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml"
	"github.com/googleapis/genai-toolbox/internal/sources"
	"github.com/googleapis/genai-toolbox/internal/util"
	trinogo "github.com/trinodb/trino-go-client/trino"
	"go.opentelemetry.io/otel/trace"
)

const SourceType string = "trino"

// validate interface
var _ sources.SourceConfig = Config{}

func init() {
	if !sources.Register(SourceType, newConfig) {
		panic(fmt.Sprintf("source type %q already registered", SourceType))
	}
}

func newConfig(ctx context.Context, name string, decoder *yaml.Decoder) (sources.SourceConfig, error) {
	actual := Config{Name: name}
	if err := decoder.DecodeContext(ctx, &actual); err != nil {
		return nil, err
	}
	return actual, nil
}

type Config struct {
	Name                   string `yaml:"name" validate:"required"`
	Type                   string `yaml:"type" validate:"required"`
	Host                   string `yaml:"host" validate:"required"`
	Port                   string `yaml:"port" validate:"required"`
	User                   string `yaml:"user"`
	Password               string `yaml:"password"`
	Catalog                string `yaml:"catalog" validate:"required"`
	Schema                 string `yaml:"schema" validate:"required"`
	QueryTimeout           string `yaml:"queryTimeout"`
	AccessToken            string `yaml:"accessToken"`
	KerberosEnabled        bool   `yaml:"kerberosEnabled"`
	SSLEnabled             bool   `yaml:"sslEnabled"`
	SSLCertPath            string `yaml:"sslCertPath"`
	SSLCert                string `yaml:"sslCert"`
	DisableSslVerification bool   `yaml:"disableSslVerification"`
	ReadOnlyMode           bool   `yaml:"readOnlyMode"`
	UseClientAuth          string `yaml:"useClientAuth"`
}

func (r Config) SourceConfigType() string {
	return SourceType
}

func (r Config) Initialize(ctx context.Context, tracer trace.Tracer) (sources.Source, error) {
	pool, err := initTrinoConnectionPool(ctx, tracer, r)
	if err != nil {
		return nil, fmt.Errorf("unable to create pool: %w", err)
	}

	err = pool.PingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to connect successfully: %w", err)
	}

	s := &Source{
		Config:    r,
		Pool:      pool,
		userPools: make(map[string]*userPool),
	}
	return s, nil
}

var _ sources.Source = &Source{}

// maxUserPools limits the number of cached per-user connection pools.
// When exceeded, one pool is evicted to make room.
const maxUserPools = 100

// userPool wraps a per-user *sql.DB with a last-accessed timestamp for LRU eviction.
type userPool struct {
	db       *sql.DB
	lastUsed time.Time
}

type Source struct {
	Config
	Pool        *sql.DB
	userPoolsMu sync.Mutex
	userPools   map[string]*userPool // per-user connection pools
}

func (s *Source) SourceType() string {
	return SourceType
}

func (s *Source) ToConfig() sources.SourceConfig {
	return s.Config
}

func (s *Source) TrinoDB() *sql.DB {
	return s.Pool
}

func (s *Source) IsReadOnly() bool {
	return s.ReadOnlyMode
}

const defaultClientAuthHeader = "X-Authenticated-User"

// useClientAuthEnabled returns true if per-user identity propagation is enabled.
// Empty string and "false" mean disabled; "true" and any other value mean enabled.
func useClientAuthEnabled(value string) bool {
	v := strings.TrimSpace(strings.ToLower(value))
	return v != "" && v != "false"
}

// UseClientAuthorization returns true if per-user identity propagation is enabled.
func (s *Source) UseClientAuthorization() bool {
	return useClientAuthEnabled(s.UseClientAuth)
}

// GetAuthTokenHeaderName returns the HTTP header name to read the user identity from.
// "true" maps to the default header "X-Authenticated-User"; any other non-empty,
// non-"false" value is treated as a custom header name.
func (s *Source) GetAuthTokenHeaderName() string {
	if !s.UseClientAuthorization() {
		return "Authorization"
	}
	v := strings.TrimSpace(strings.ToLower(s.UseClientAuth))
	if v == "true" {
		return defaultClientAuthHeader
	}
	return strings.TrimSpace(s.UseClientAuth)
}

// getPoolForUser returns a cached *sql.DB connection pool for the given user.
// Creates a new pool on first access for that user. When the cache exceeds
// maxUserPools, the least-recently-used pool is evicted.
func (s *Source) getPoolForUser(user string) (*sql.DB, error) {
	s.userPoolsMu.Lock()
	if entry, ok := s.userPools[user]; ok {
		entry.lastUsed = time.Now()
		s.userPoolsMu.Unlock()
		return entry.db, nil
	}
	s.userPoolsMu.Unlock()

	perUserCfg := s.Config
	perUserCfg.User = user
	perUserCfg.Password = ""
	perUserCfg.AccessToken = ""
	dsn, err := buildTrinoDSN(perUserCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build per-user DSN: %w", err)
	}

	// Reuse the custom client registered at source init for SSL verification bypass
	if s.DisableSslVerification {
		dsn = fmt.Sprintf("%s&custom_client=%s", dsn, insecureClientName(s.Name))
	}

	db, err := sql.Open("trino", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open per-user connection: %w", err)
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(time.Hour)

	s.userPoolsMu.Lock()

	// Double-check: another goroutine may have created it while we built the pool
	if existing, ok := s.userPools[user]; ok {
		existing.lastUsed = time.Now()
		s.userPoolsMu.Unlock()
		db.Close()
		return existing.db, nil
	}

	// Evict the least-recently-used pool if at capacity.
	var evicted *sql.DB
	if len(s.userPools) >= maxUserPools {
		var lruKey string
		var lruTime time.Time
		for k, v := range s.userPools {
			if lruKey == "" || v.lastUsed.Before(lruTime) {
				lruKey = k
				lruTime = v.lastUsed
			}
		}
		evicted = s.userPools[lruKey].db
		delete(s.userPools, lruKey)
	}

	s.userPools[user] = &userPool{db: db, lastUsed: time.Now()}
	s.userPoolsMu.Unlock()

	// Close evicted pool outside the lock. sql.DB.Close() drains in-flight
	// queries before returning, so this runs in a goroutine to avoid blocking
	// the caller.
	if evicted != nil {
		go evicted.Close()
	}

	return db, nil
}

// RunSQLAsUser executes a SQL statement as a specific user identity.
// Used when per-user identity propagation is enabled (useClientAuth is set).
func (s *Source) RunSQLAsUser(ctx context.Context, statement string, params []any, user string) (any, error) {
	if err := CheckReadOnly(s.ReadOnlyMode, statement); err != nil {
		return nil, err
	}

	pool, err := s.getPoolForUser(user)
	if err != nil {
		return nil, err
	}
	return executeQuery(ctx, pool, statement, params)
}

// readOnlyAllowedPrefixes are the SQL statement prefixes allowed in read-only mode.
var readOnlyAllowedPrefixes = []string{
	"SELECT",
	"WITH",
	"SHOW",
	"DESCRIBE",
	"EXPLAIN",
	"VALUES",
}

// normalizeResult holds the output of normalizeSQL: the cleaned SQL text and
// whether a semicolon was found outside string literals and comments.
type normalizeResult struct {
	sql            string
	hasSemicolon   bool
}

// normalizeSQL strips SQL comments (both line and block) while respecting
// string literals, then collapses whitespace. It also detects semicolons
// outside of quoted strings in a single pass.
func normalizeSQL(sql string) normalizeResult {
	var buf strings.Builder
	buf.Grow(len(sql))
	hasSemicolon := false
	i := 0
	for i < len(sql) {
		ch := sql[i]
		switch {
		// Single-quoted string literal — copy verbatim
		case ch == '\'':
			buf.WriteByte(ch)
			i++
			for i < len(sql) {
				if sql[i] == '\'' {
					buf.WriteByte(sql[i])
					i++
					// escaped quote ''
					if i < len(sql) && sql[i] == '\'' {
						buf.WriteByte(sql[i])
						i++
						continue
					}
					break
				}
				buf.WriteByte(sql[i])
				i++
			}
		// Double-quoted identifier — copy verbatim
		case ch == '"':
			buf.WriteByte(ch)
			i++
			for i < len(sql) {
				if sql[i] == '"' {
					buf.WriteByte(sql[i])
					i++
					if i < len(sql) && sql[i] == '"' {
						buf.WriteByte(sql[i])
						i++
						continue
					}
					break
				}
				buf.WriteByte(sql[i])
				i++
			}
		// Line comment — skip to end of line
		case ch == '-' && i+1 < len(sql) && sql[i+1] == '-':
			i += 2
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			buf.WriteByte(' ')
		// Block comment — skip to closing */
		case ch == '/' && i+1 < len(sql) && sql[i+1] == '*':
			i += 2
			for i+1 < len(sql) {
				if sql[i] == '*' && sql[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			buf.WriteByte(' ')
		case ch == ';':
			hasSemicolon = true
			buf.WriteByte(ch)
			i++
		default:
			buf.WriteByte(ch)
			i++
		}
	}
	return normalizeResult{
		sql:          collapseWhitespace(buf.String()),
		hasSemicolon: hasSemicolon,
	}
}

var whitespaceRe = regexp.MustCompile(`\s+`)

func collapseWhitespace(s string) string {
	return strings.TrimSpace(whitespaceRe.ReplaceAllString(s, " "))
}

// CheckReadOnly validates that a statement is read-only when read-only mode is enabled.
// It strips SQL comments, rejects multi-statement SQL (semicolons outside string
// literals), and checks for an allowed statement prefix.
func CheckReadOnly(readOnly bool, statement string) error {
	if !readOnly {
		return nil
	}
	result := normalizeSQL(statement)
	if result.hasSemicolon {
		return fmt.Errorf("statement blocked by read-only mode: multiple statements (semicolons) are not allowed")
	}
	upper := strings.ToUpper(result.sql)
	for _, prefix := range readOnlyAllowedPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return nil
		}
	}
	return fmt.Errorf("statement blocked by read-only mode: only SELECT, WITH, SHOW, DESCRIBE, EXPLAIN, and VALUES statements are allowed")
}

func (s *Source) RunSQL(ctx context.Context, statement string, params []any) (any, error) {
	if err := CheckReadOnly(s.ReadOnlyMode, statement); err != nil {
		return nil, err
	}
	return executeQuery(ctx, s.Pool, statement, params)
}

// executeQuery runs a SQL statement against a given *sql.DB and returns the results.
func executeQuery(ctx context.Context, db *sql.DB, statement string, params []any) (any, error) {
	results, err := db.QueryContext(ctx, statement, params...)
	if err != nil {
		return nil, fmt.Errorf("unable to execute query: %w", err)
	}
	defer results.Close()

	cols, err := results.Columns()
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve column names: %w", err)
	}

	// create an array of values for each column, which can be re-used to scan each row
	rawValues := make([]any, len(cols))
	values := make([]any, len(cols))
	for i := range rawValues {
		values[i] = &rawValues[i]
	}

	var out []any
	for results.Next() {
		err := results.Scan(values...)
		if err != nil {
			return nil, fmt.Errorf("unable to parse row: %w", err)
		}
		vMap := make(map[string]any)
		for i, name := range cols {
			val := rawValues[i]
			if val == nil {
				vMap[name] = nil
				continue
			}

			// Convert byte arrays to strings for text fields
			if b, ok := val.([]byte); ok {
				vMap[name] = string(b)
			} else {
				vMap[name] = val
			}
		}
		out = append(out, vMap)
	}

	if err := results.Err(); err != nil {
		return nil, fmt.Errorf("errors encountered during row iteration: %w", err)
	}

	return out, nil
}

func initTrinoConnectionPool(ctx context.Context, tracer trace.Tracer, cfg Config) (*sql.DB, error) {
	//nolint:all // Reassigned ctx
	ctx, span := sources.InitConnectionSpan(ctx, tracer, SourceType, cfg.Name)
	defer span.End()

	// Build Trino DSN
	dsn, err := buildTrinoDSN(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build DSN: %w", err)
	}

	logger, err := util.LoggerFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get logger from ctx: %s", err)
	}

	if cfg.DisableSslVerification {
		logger.WarnContext(ctx, "SSL verification is disabled for trino source %s. This is an insecure setting and should not be used in production.\n", cfg.Name)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		clientName := insecureClientName(cfg.Name)
		if err := trinogo.RegisterCustomClient(clientName, client); err != nil {
			return nil, fmt.Errorf("failed to register custom client: %w", err)
		}
		dsn = fmt.Sprintf("%s&custom_client=%s", dsn, clientName)
	}

	db, err := sql.Open("trino", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open connection: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)

	return db, nil
}

func insecureClientName(sourceName string) string {
	return fmt.Sprintf("insecure_trino_client_%s", sourceName)
}

func buildTrinoDSN(cfg Config) (string, error) {
	// Build query parameters
	query := url.Values{}
	query.Set("catalog", cfg.Catalog)
	query.Set("schema", cfg.Schema)
	if cfg.QueryTimeout != "" {
		query.Set("queryTimeout", cfg.QueryTimeout)
	}
	if cfg.AccessToken != "" {
		query.Set("accessToken", cfg.AccessToken)
	}
	if cfg.KerberosEnabled {
		query.Set("KerberosEnabled", "true")
	}
	if cfg.SSLCertPath != "" {
		query.Set("sslCertPath", cfg.SSLCertPath)
	}
	if cfg.SSLCert != "" {
		query.Set("sslCert", cfg.SSLCert)
	}

	// Build URL
	scheme := "http"
	if cfg.SSLEnabled {
		scheme = "https"
	}

	u := &url.URL{
		Scheme:   scheme,
		Host:     fmt.Sprintf("%s:%s", cfg.Host, cfg.Port),
		RawQuery: query.Encode(),
	}

	// Only set user and password if not empty
	if cfg.User != "" && cfg.Password != "" {
		u.User = url.UserPassword(cfg.User, cfg.Password)
	} else if cfg.User != "" {
		u.User = url.User(cfg.User)
	}

	return u.String(), nil
}
