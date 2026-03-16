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
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/googleapis/genai-toolbox/internal/server"
	"github.com/googleapis/genai-toolbox/internal/sources"
	"github.com/googleapis/genai-toolbox/internal/testutils"
	"github.com/googleapis/genai-toolbox/internal/util"
)

func TestBuildTrinoDSN(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		want    string
		wantErr bool
	}{
		{
			name: "basic configuration",
			cfg:  Config{Host: "localhost", Port: "8080", User: "testuser", Catalog: "hive", Schema: "default"},
			want: "http://testuser@localhost:8080?catalog=hive&schema=default",
		},
		{
			name: "with SSL cert path and cert",
			cfg:  Config{Host: "localhost", Port: "8443", User: "testuser", Catalog: "hive", Schema: "default", SSLEnabled: true, SSLCertPath: "/path/to/cert.pem", SSLCert: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"},
			want: "https://testuser@localhost:8443?catalog=hive&schema=default&sslCert=-----BEGIN+CERTIFICATE-----%0A...%0A-----END+CERTIFICATE-----%0A&sslCertPath=%2Fpath%2Fto%2Fcert.pem",
		},
		{
			name: "with password",
			cfg:  Config{Host: "localhost", Port: "8080", User: "testuser", Password: "testpass", Catalog: "hive", Schema: "default"},
			want: "http://testuser:testpass@localhost:8080?catalog=hive&schema=default",
		},
		{
			name: "with SSL",
			cfg:  Config{Host: "localhost", Port: "8443", User: "testuser", Catalog: "hive", Schema: "default", SSLEnabled: true},
			want: "https://testuser@localhost:8443?catalog=hive&schema=default",
		},
		{
			name: "with access token",
			cfg:  Config{Host: "localhost", Port: "8080", User: "testuser", Catalog: "hive", Schema: "default", AccessToken: "jwt-token-here"},
			want: "http://testuser@localhost:8080?accessToken=jwt-token-here&catalog=hive&schema=default",
		},
		{
			name: "with kerberos",
			cfg:  Config{Host: "localhost", Port: "8080", User: "testuser", Catalog: "hive", Schema: "default", KerberosEnabled: true},
			want: "http://testuser@localhost:8080?KerberosEnabled=true&catalog=hive&schema=default",
		},
		{
			name: "with query timeout",
			cfg:  Config{Host: "localhost", Port: "8080", User: "testuser", Catalog: "hive", Schema: "default", QueryTimeout: "30m"},
			want: "http://testuser@localhost:8080?catalog=hive&queryTimeout=30m&schema=default",
		},
		{
			name: "with source",
			cfg:  Config{Host: "localhost", Port: "8080", User: "testuser", Catalog: "hive", Schema: "default", Source: "trino-mcp"},
			want: "http://testuser@localhost:8080?catalog=hive&schema=default&source=trino-mcp",
		},
		{
			name: "with client tags",
			cfg:  Config{Host: "localhost", Port: "8080", User: "testuser", Catalog: "hive", Schema: "default", ClientTags: "mcp,ai-assistant"},
			want: "http://testuser@localhost:8080?catalog=hive&clientTags=mcp%2Cai-assistant&schema=default",
		},
		{
			name: "anonymous access (empty user)",
			cfg:  Config{Host: "localhost", Port: "8080", Catalog: "hive", Schema: "default"},
			want: "http://localhost:8080?catalog=hive&schema=default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildTrinoDSN(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildTrinoDSN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("buildTrinoDSN() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUseClientAuthorization(t *testing.T) {
	tests := []struct {
		name           string
		useClientAuth  string
		wantRequired   bool
		wantHeaderName string
	}{
		{name: "disabled when empty", useClientAuth: "", wantRequired: false, wantHeaderName: "Authorization"},
		{name: "disabled when false", useClientAuth: "false", wantRequired: false, wantHeaderName: "Authorization"},
		{name: "disabled when False", useClientAuth: "False", wantRequired: false, wantHeaderName: "Authorization"},
		{name: "disabled when FALSE", useClientAuth: "FALSE", wantRequired: false, wantHeaderName: "Authorization"},
		{name: "enabled with true uses default header", useClientAuth: "true", wantRequired: true, wantHeaderName: "X-Authenticated-User"},
		{name: "enabled with True uses default header", useClientAuth: "True", wantRequired: true, wantHeaderName: "X-Authenticated-User"},
		{name: "enabled with custom header", useClientAuth: "X-Authenticated-User", wantRequired: true, wantHeaderName: "X-Authenticated-User"},
		{name: "enabled with another header", useClientAuth: "X-Remote-User", wantRequired: true, wantHeaderName: "X-Remote-User"},
		{name: "trims whitespace from custom header", useClientAuth: "  X-Remote-User  ", wantRequired: true, wantHeaderName: "X-Remote-User"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Source{Config: Config{UseClientAuth: tt.useClientAuth}}
			if got := s.UseClientAuthorization(); got != tt.wantRequired {
				t.Errorf("UseClientAuthorization() = %v, want %v", got, tt.wantRequired)
			}
			if got := s.GetAuthTokenHeaderName(); got != tt.wantHeaderName {
				t.Errorf("GetAuthTokenHeaderName() = %q, want %q", got, tt.wantHeaderName)
			}
		})
	}
}

func TestResolveClientTags(t *testing.T) {
	tests := []struct {
		name        string
		clientTags  string
		headerValue string
		want        string
	}{
		{name: "static only", clientTags: "mcp", want: "mcp"},
		{name: "header only", headerValue: "claude-code", want: "claude-code"},
		{name: "merged", clientTags: "mcp", headerValue: "claude-code", want: "mcp,claude-code"},
		{name: "empty header value uses static", clientTags: "mcp", headerValue: "", want: "mcp"},
		{name: "no config no header returns empty", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Source{Config: Config{ClientTags: tt.clientTags}}
			ctx := context.Background()
			h := http.Header{}
			if tt.headerValue != "" {
				h.Set("X-Trino-Client-Tags", tt.headerValue)
			}
			ctx = util.WithRequestHeaders(ctx, h)
			if got := s.resolveClientTags(ctx); got != tt.want {
				t.Errorf("resolveClientTags() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_checkReadOnly(t *testing.T) {
	tests := []struct {
		name      string
		readOnly  bool
		statement string
		wantErr   bool
	}{
		// Read-only mode disabled: everything passes
		{name: "disabled allows INSERT", readOnly: false, statement: "INSERT INTO t VALUES (1)", wantErr: false},

		// Read-only mode enabled: allowed statements
		{name: "allows SELECT", readOnly: true, statement: "SELECT * FROM t", wantErr: false},
		{name: "allows select lowercase", readOnly: true, statement: "select * from t", wantErr: false},
		{name: "allows WITH (CTE)", readOnly: true, statement: "WITH cte AS (SELECT 1) SELECT * FROM cte", wantErr: false},
		{name: "allows SHOW", readOnly: true, statement: "SHOW CATALOGS", wantErr: false},
		{name: "allows DESCRIBE", readOnly: true, statement: "DESCRIBE my_table", wantErr: false},
		{name: "allows EXPLAIN", readOnly: true, statement: "EXPLAIN SELECT 1", wantErr: false},
		{name: "allows VALUES", readOnly: true, statement: "VALUES 1, 2, 3", wantErr: false},
		{name: "allows leading whitespace", readOnly: true, statement: "  SELECT 1", wantErr: false},

		// Read-only mode enabled: blocked statements
		{name: "blocks INSERT", readOnly: true, statement: "INSERT INTO t VALUES (1)", wantErr: true},
		{name: "blocks UPDATE", readOnly: true, statement: "UPDATE t SET x = 1", wantErr: true},
		{name: "blocks DELETE", readOnly: true, statement: "DELETE FROM t", wantErr: true},
		{name: "blocks MERGE", readOnly: true, statement: "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.x = s.x", wantErr: true},
		{name: "blocks CREATE", readOnly: true, statement: "CREATE TABLE t (id INT)", wantErr: true},
		{name: "blocks ALTER", readOnly: true, statement: "ALTER TABLE t ADD COLUMN x INT", wantErr: true},
		{name: "blocks DROP", readOnly: true, statement: "DROP TABLE t", wantErr: true},
		{name: "blocks TRUNCATE", readOnly: true, statement: "TRUNCATE TABLE t", wantErr: true},
		{name: "blocks GRANT", readOnly: true, statement: "GRANT SELECT ON t TO user1", wantErr: true},
		{name: "blocks REVOKE", readOnly: true, statement: "REVOKE SELECT ON t FROM user1", wantErr: true},
		{name: "blocks SET", readOnly: true, statement: "SET SESSION query_max_run_time = '10m'", wantErr: true},
		{name: "blocks CALL", readOnly: true, statement: "CALL system.runtime.kill_query('abc')", wantErr: true},
		{name: "blocks USE", readOnly: true, statement: "USE hive.default", wantErr: true},
		{name: "blocks RENAME", readOnly: true, statement: "RENAME TABLE t TO t2", wantErr: true},

		// Comment-based bypass attempts
		{name: "blocks line comment hiding DELETE", readOnly: true, statement: "-- SELECT\nDELETE FROM t", wantErr: true},
		{name: "blocks block comment hiding DELETE", readOnly: true, statement: "/* SELECT */ DELETE FROM t", wantErr: true},
		{name: "allows SELECT with trailing comment", readOnly: true, statement: "SELECT 1 -- comment", wantErr: false},
		{name: "allows SELECT with block comment", readOnly: true, statement: "SELECT /* comment */ * FROM t", wantErr: false},

		// Multi-statement bypass attempts
		{name: "blocks semicolon multi-statement", readOnly: true, statement: "SELECT 1; DROP TABLE t", wantErr: true},
		{name: "blocks semicolon at end with mutation", readOnly: true, statement: "SELECT 1; DELETE FROM t;", wantErr: true},
		{name: "allows semicolon inside single-quoted literal", readOnly: true, statement: "SELECT * FROM t WHERE x = 'a;b'", wantErr: false},
		{name: "allows semicolon inside double-quoted identifier", readOnly: true, statement: `SELECT * FROM t WHERE "col;name" = 1`, wantErr: false},
		{name: "blocks semicolon outside quotes", readOnly: true, statement: "SELECT 'ok'; DROP TABLE t", wantErr: true},

		// Combined comment + semicolon
		{name: "blocks comment then semicolon", readOnly: true, statement: "-- safe\nSELECT 1; DROP TABLE t", wantErr: true},

		// String-literal-aware comment stripping (issue: -- inside quotes must not be treated as comment)
		{name: "blocks -- inside single quotes followed by semicolon", readOnly: true, statement: "SELECT '--'; DELETE FROM t", wantErr: true},
		{name: "blocks /* inside single quotes followed by semicolon", readOnly: true, statement: "SELECT '/*'; DELETE FROM t", wantErr: true},
		{name: "allows -- inside single-quoted string without semicolon", readOnly: true, statement: "SELECT '--' FROM t", wantErr: false},
		{name: "allows /* inside single-quoted string without semicolon", readOnly: true, statement: "SELECT '/* not a comment */' FROM t", wantErr: false},
		{name: "blocks block comment hiding mutation outside quotes", readOnly: true, statement: "SELECT 'ok' /* legit */ ; DELETE FROM t", wantErr: true},
		{name: "handles escaped single quotes", readOnly: true, statement: "SELECT 'it''s fine' FROM t", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkReadOnly(tt.readOnly, tt.statement)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkReadOnly(%v, %q) error = %v, wantErr %v", tt.readOnly, tt.statement, err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeSQL(t *testing.T) {
	tests := []struct {
		name             string
		in               string
		wantSQL          string
		wantHasSemicolon bool
	}{
		{name: "no comments", in: "SELECT * FROM t", wantSQL: "SELECT * FROM t"},
		{name: "line comment", in: "SELECT 1 -- comment", wantSQL: "SELECT 1"},
		{name: "line comment before statement", in: "-- comment\nSELECT 1", wantSQL: "SELECT 1"},
		{name: "block comment", in: "SELECT /* inline */ 1", wantSQL: "SELECT 1"},
		{name: "block comment before statement", in: "/* header */ SELECT 1", wantSQL: "SELECT 1"},
		{name: "multiline block comment", in: "/* line1\nline2 */ SELECT 1", wantSQL: "SELECT 1"},
		{name: "multiple comments", in: "-- first\n/* second */ SELECT -- third\n1", wantSQL: "SELECT 1"},
		{name: "collapses whitespace", in: "  SELECT  *  FROM  t  ", wantSQL: "SELECT * FROM t"},
		{name: "preserves -- inside single quotes", in: "SELECT '--' FROM t", wantSQL: "SELECT '--' FROM t"},
		{name: "preserves /* inside single quotes", in: "SELECT '/* x */' FROM t", wantSQL: "SELECT '/* x */' FROM t"},
		{name: "preserves -- inside double quotes", in: `SELECT "--" FROM t`, wantSQL: `SELECT "--" FROM t`},
		{name: "handles escaped single quotes", in: "SELECT 'it''s' FROM t", wantSQL: "SELECT 'it''s' FROM t"},
		// semicolon detection
		{name: "no semicolon", in: "SELECT 1", wantHasSemicolon: false, wantSQL: "SELECT 1"},
		{name: "bare semicolon", in: "SELECT 1; DROP TABLE t", wantHasSemicolon: true, wantSQL: "SELECT 1; DROP TABLE t"},
		{name: "semicolon in single quotes", in: "SELECT 'a;b'", wantHasSemicolon: false, wantSQL: "SELECT 'a;b'"},
		{name: "semicolon in double quotes", in: `SELECT "a;b"`, wantHasSemicolon: false, wantSQL: `SELECT "a;b"`},
		{name: "semicolon outside after quote", in: "SELECT 'ok'; DROP TABLE t", wantHasSemicolon: true, wantSQL: "SELECT 'ok'; DROP TABLE t"},
		{name: "trailing semicolon", in: "SELECT 1;", wantHasSemicolon: true, wantSQL: "SELECT 1;"},
		{name: "semicolon in comment", in: "SELECT 1 -- ; comment", wantHasSemicolon: false, wantSQL: "SELECT 1"},
		// unterminated constructs
		{name: "unterminated block comment", in: "SELECT 1 /* oops", wantSQL: "SELECT 1"},
		{name: "unterminated single quote", in: "SELECT 'abc", wantSQL: "SELECT 'abc"},
		{name: "unterminated double quote", in: `SELECT "abc`, wantSQL: `SELECT "abc`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSQL(tt.in)
			if got.normalized != tt.wantSQL {
				t.Errorf("normalizeSQL(%q).sql = %q, want %q", tt.in, got.normalized, tt.wantSQL)
			}
			if got.hasSemicolon != tt.wantHasSemicolon {
				t.Errorf("normalizeSQL(%q).hasSemicolon = %v, want %v", tt.in, got.hasSemicolon, tt.wantHasSemicolon)
			}
		})
	}
}

func TestPrepareImpersonatedParams(t *testing.T) {
	tests := []struct {
		name     string
		params   []any
		user     string
		wantUser string // expected value in the named arg
		wantErr  bool
	}{
		// Valid users
		{name: "valid user appends named arg", user: "alice", wantUser: "alice"},
		{name: "trims whitespace", user: "  alice  ", wantUser: "alice"},
		{name: "user with dots and dashes", user: "alice.bob-test", wantUser: "alice.bob-test"},
		{name: "user with underscores", user: "svc_account", wantUser: "svc_account"},
		{name: "preserves existing params", user: "alice", params: []any{42}, wantUser: "alice"},
		{name: "exactly 64 chars (max allowed)", user: "abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", wantUser: "abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},

		// Invalid users — empty
		{name: "empty string", user: "", wantErr: true},
		{name: "whitespace only", user: "   ", wantErr: true},

		// Invalid users — pattern mismatch
		{name: "too short", user: "ab", wantErr: true},
		{name: "starts with digit", user: "1alice", wantErr: true},
		{name: "rejects uppercase", user: "Alice", wantErr: true},
		{name: "contains space", user: "alice bob", wantErr: true},
		{name: "contains slash", user: "alice/bob", wantErr: true},
		{name: "65 chars exceeds max", user: "abbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := prepareImpersonatedParams(tt.params, tt.user)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// The last element must be the sql.Named arg
			last := got[len(got)-1]
			named, ok := last.(sql.NamedArg)
			if !ok {
				t.Fatalf("last param is %T, want sql.NamedArg", last)
			}
			if named.Name != trinoUserHeader {
				t.Errorf("named arg name = %q, want %q", named.Name, trinoUserHeader)
			}
			if named.Value != tt.wantUser {
				t.Errorf("named arg value = %q, want %q", named.Value, tt.wantUser)
			}

			// Original params should be preserved before the named arg
			for i, p := range tt.params {
				if got[i] != p {
					t.Errorf("params[%d] = %v, want %v", i, got[i], p)
				}
			}

			// Result must be a fresh slice (no aliasing)
			if len(tt.params) > 0 && &got[0] == &tt.params[0] {
				t.Error("returned slice aliases input params backing array")
			}
		})
	}
}

// TestTrinoDriverSendsImpersonationHeader verifies that the trino-go-client
// actually sends X-Trino-User as an HTTP header when sql.Named("X-Trino-User", ...)
// is passed as a query arg. This is a regression guard for client library upgrades.
func TestTrinoDriverSendsImpersonationHeader(t *testing.T) {
	var mu sync.Mutex
	var capturedUser string

	// Minimal fake Trino server that captures X-Trino-User and returns an empty result set.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if v := r.Header.Get("X-Trino-User"); v != "" {
			capturedUser = v
		}
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":      "test_query_1",
			"infoUri": "http://localhost/query/test_query_1",
			"stats": map[string]any{
				"state":              "FINISHED",
				"progressPercentage": 100.0,
			},
			"columns": []map[string]any{
				{"name": "dummy", "type": "integer"},
			},
		})
	}))
	t.Cleanup(ts.Close)

	db, err := sql.Open("trino", ts.URL+"?catalog=test&schema=default")
	if err != nil {
		t.Fatalf("failed to open trino connection: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	rows, err := db.Query("SELECT 1", sql.Named("X-Trino-User", "impersonated_user"))
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	rows.Close()

	mu.Lock()
	defer mu.Unlock()
	if capturedUser != "impersonated_user" {
		t.Errorf("X-Trino-User header = %q, want %q", capturedUser, "impersonated_user")
	}
}

func TestParseFromYamlTrino(t *testing.T) {
	tcs := []struct {
		desc string
		in   string
		want server.SourceConfigs
	}{
		{
			desc: "basic example",
			in: `
			kind: sources
			name: my-trino-instance
			type: trino
			host: localhost
			port: "8080"
			user: testuser
			catalog: hive
			schema: default
			`,
			want: map[string]sources.SourceConfig{
				"my-trino-instance": Config{
					Name:    "my-trino-instance",
					Type:    SourceType,
					Host:    "localhost",
					Port:    "8080",
					User:    "testuser",
					Catalog: "hive",
					Schema:  "default",
				},
			},
		},
		{
			desc: "example with optional fields",
			in: `
			kind: sources
			name: my-trino-instance
			type: trino
			host: localhost
			port: "8443"
			user: testuser
			password: testpass
			catalog: hive
			schema: default
			queryTimeout: "30m"
			accessToken: "jwt-token-here"
			kerberosEnabled: true
			sslEnabled: true
			`,
			want: map[string]sources.SourceConfig{
				"my-trino-instance": Config{
					Name:            "my-trino-instance",
					Type:            SourceType,
					Host:            "localhost",
					Port:            "8443",
					User:            "testuser",
					Password:        "testpass",
					Catalog:         "hive",
					Schema:          "default",
					QueryTimeout:    "30m",
					AccessToken:     "jwt-token-here",
					KerberosEnabled: true,
					SSLEnabled:      true,
				},
			},
		},
		{
			desc: "anonymous access without user",
			in: `
			kind: sources
			name: my-trino-anonymous
			type: trino
			host: localhost
			port: "8080"
			catalog: hive
			schema: default
			`,
			want: map[string]sources.SourceConfig{
				"my-trino-anonymous": Config{
					Name:    "my-trino-anonymous",
					Type:    SourceType,
					Host:    "localhost",
					Port:    "8080",
					Catalog: "hive",
					Schema:  "default",
				},
			},
		},
		{
			desc: "example with SSL cert path and cert",
			in: `
			kind: sources
			name: my-trino-ssl-cert
			type: trino
			host: localhost
			port: "8443"
			user: testuser
			catalog: hive
			schema: default
			sslEnabled: true
			sslCertPath: /path/to/cert.pem
			sslCert: |-
						-----BEGIN CERTIFICATE-----
						...
						-----END CERTIFICATE-----
			disableSslVerification: true
			`,
			want: map[string]sources.SourceConfig{
				"my-trino-ssl-cert": Config{
					Name:                   "my-trino-ssl-cert",
					Type:                   SourceType,
					Host:                   "localhost",
					Port:                   "8443",
					User:                   "testuser",
					Catalog:                "hive",
					Schema:                 "default",
					SSLEnabled:             true,
					SSLCertPath:            "/path/to/cert.pem",
					SSLCert:                "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
					DisableSslVerification: true,
				},
			},
		},
		{
			desc: "with readOnlyMode and useClientAuth",
			in: `
			kind: sources
			name: my-trino-readonly
			type: trino
			host: localhost
			port: "8080"
			user: trino
			catalog: hive
			schema: default
			readOnlyMode: true
			useClientAuth: X-Authenticated-User
			`,
			want: map[string]sources.SourceConfig{
				"my-trino-readonly": Config{
					Name:          "my-trino-readonly",
					Type:          SourceType,
					Host:          "localhost",
					Port:          "8080",
					User:          "trino",
					Catalog:       "hive",
					Schema:        "default",
					ReadOnlyMode:  true,
					UseClientAuth: "X-Authenticated-User",
				},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			got, _, _, _, _, _, err := server.UnmarshalResourceConfig(context.Background(), testutils.FormatYaml(tc.in))
			if err != nil {
				t.Fatalf("unable to unmarshal: %s", err)
			}
			if !cmp.Equal(tc.want, got) {
				t.Fatalf("incorrect parse: want %v, got %v", tc.want, got)
			}
		})
	}
}
