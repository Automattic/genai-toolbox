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
	Source                 string `yaml:"source"`
	ClientTags             string `yaml:"clientTags"`
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
		Config: r,
		Pool:   pool,
	}
	return s, nil
}

var _ sources.Source = &Source{}

type Source struct {
	Config
	Pool *sql.DB
}

func (s *Source) SourceType() string {
	return SourceType
}

func (s *Source) ToConfig() sources.SourceConfig {
	return s.Config
}

const defaultClientAuthHeader = "X-Authenticated-User"

// trinoUserHeader is the HTTP header the trino-go-client uses to set the
// session user identity. Used with sql.Named to override per query.
const trinoUserHeader = "X-Trino-User"

// trinoClientTagsHeader is the HTTP header the trino-go-client uses to set
// client tags. Used with sql.Named to override per query.
const trinoClientTagsHeader = "X-Trino-Client-Tags"

// validUsernameRe matches allowed usernames for impersonation.
// Constraining the pattern prevents malformed or injected identities from
// reaching Trino, failing fast in MCP instead.
var validUsernameRe = regexp.MustCompile(`^[a-z][a-z0-9._-]{2,63}$`)

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

// appendNamedParam appends a single sql.Named parameter to params, returning
// a fresh slice to avoid aliasing the caller's backing array.
func appendNamedParam(params []any, name string, value any) []any {
	out := make([]any, len(params)+1)
	copy(out, params)
	out[len(params)] = sql.Named(name, value)
	return out
}

// prepareImpersonatedParams validates the user identity and returns a new
// params slice with sql.Named("X-Trino-User", user) appended.
func prepareImpersonatedParams(params []any, user string) ([]any, error) {
	user = strings.TrimSpace(user)
	if user == "" {
		return nil, fmt.Errorf("user identity is required for per-user query execution")
	}
	if !validUsernameRe.MatchString(user) {
		return nil, fmt.Errorf("invalid user identity %q: must match %s", user, validUsernameRe.String())
	}
	return appendNamedParam(params, trinoUserHeader, user), nil
}

// resolveClientTags merges static client tags from config with per-request
// tags from the X-Trino-Client-Tags header in the incoming request. Returns
// the comma-separated result, or empty string if no tags are present.
func (s *Source) resolveClientTags(ctx context.Context) string {
	var parts []string
	if s.ClientTags != "" {
		parts = append(parts, s.ClientTags)
	}
	if h := util.RequestHeadersFromContext(ctx); h != nil {
		if v := strings.TrimSpace(h.Get(trinoClientTagsHeader)); v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ",")
}

// appendClientTags appends sql.Named("X-Trino-Client-Tags", tags) to params
// if any client tags are resolved. Returns params unchanged when tags is empty.
func appendClientTags(params []any, tags string) []any {
	if tags == "" {
		return params
	}
	return appendNamedParam(params, trinoClientTagsHeader, tags)
}

// RunSQLAsUser executes a SQL statement as a specific user identity.
// The shared pool authenticates with service account credentials while
// the trino-go-client's sql.Named("X-Trino-User", user) overrides the
// session identity per query, enabling Trino impersonation.
func (s *Source) RunSQLAsUser(ctx context.Context, statement string, params []any, user string) (any, error) {
	if err := checkReadOnly(s.ReadOnlyMode, statement); err != nil {
		return nil, err
	}
	params, err := prepareImpersonatedParams(params, user)
	if err != nil {
		return nil, err
	}
	params = appendClientTags(params, s.resolveClientTags(ctx))
	return executeQuery(ctx, s.Pool, statement, params)
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
	normalized     string
	hasSemicolon   bool
}

// normalizeSQL strips SQL comments (both line and block) while respecting
// string literals, then collapses whitespace. It also detects semicolons
// outside of quoted strings in a single pass.
func normalizeSQL(rawSQL string) normalizeResult {
	var buf strings.Builder
	buf.Grow(len(rawSQL))
	hasSemicolon := false
	i := 0
	for i < len(rawSQL) {
		ch := rawSQL[i]
		switch {
		// Single-quoted string literal — copy verbatim
		case ch == '\'':
			buf.WriteByte(ch)
			i++
			for i < len(rawSQL) {
				if rawSQL[i] == '\'' {
					buf.WriteByte(rawSQL[i])
					i++
					// escaped quote ''
					if i < len(rawSQL) && rawSQL[i] == '\'' {
						buf.WriteByte(rawSQL[i])
						i++
						continue
					}
					break
				}
				buf.WriteByte(rawSQL[i])
				i++
			}
		// Double-quoted identifier — copy verbatim
		case ch == '"':
			buf.WriteByte(ch)
			i++
			for i < len(rawSQL) {
				if rawSQL[i] == '"' {
					buf.WriteByte(rawSQL[i])
					i++
					if i < len(rawSQL) && rawSQL[i] == '"' {
						buf.WriteByte(rawSQL[i])
						i++
						continue
					}
					break
				}
				buf.WriteByte(rawSQL[i])
				i++
			}
		// Line comment — skip to end of line
		case ch == '-' && i+1 < len(rawSQL) && rawSQL[i+1] == '-':
			i += 2
			for i < len(rawSQL) && rawSQL[i] != '\n' {
				i++
			}
			buf.WriteByte(' ')
		// Block comment — skip to closing */
		case ch == '/' && i+1 < len(rawSQL) && rawSQL[i+1] == '*':
			i += 2
			for i < len(rawSQL) {
				if rawSQL[i] == '*' && i+1 < len(rawSQL) && rawSQL[i+1] == '/' {
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
		normalized:   collapseWhitespace(buf.String()),
		hasSemicolon: hasSemicolon,
	}
}

var whitespaceRe = regexp.MustCompile(`\s+`)

func collapseWhitespace(s string) string {
	return strings.TrimSpace(whitespaceRe.ReplaceAllString(s, " "))
}

// checkReadOnly validates that a statement is read-only when read-only mode is enabled.
// It strips SQL comments, rejects multi-statement SQL (semicolons outside string
// literals), and checks for an allowed statement prefix.
func checkReadOnly(readOnly bool, statement string) error {
	if !readOnly {
		return nil
	}
	result := normalizeSQL(statement)
	if result.hasSemicolon {
		return fmt.Errorf("statement blocked by read-only mode: multiple statements (semicolons) are not allowed")
	}
	for _, prefix := range readOnlyAllowedPrefixes {
		if len(result.normalized) >= len(prefix) && strings.EqualFold(result.normalized[:len(prefix)], prefix) {
			return nil
		}
	}
	return fmt.Errorf("statement blocked by read-only mode: only SELECT, WITH, SHOW, DESCRIBE, EXPLAIN, and VALUES statements are allowed")
}

func (s *Source) RunSQL(ctx context.Context, statement string, params []any) (any, error) {
	if err := checkReadOnly(s.ReadOnlyMode, statement); err != nil {
		return nil, err
	}
	params = appendClientTags(params, s.resolveClientTags(ctx))
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
		vMap := make(map[string]any, len(cols))
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
	if cfg.Source != "" {
		query.Set("source", cfg.Source)
	}
	if cfg.ClientTags != "" {
		query.Set("clientTags", cfg.ClientTags)
	}
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
