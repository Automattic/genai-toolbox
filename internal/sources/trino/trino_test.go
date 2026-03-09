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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/googleapis/genai-toolbox/internal/server"
	"github.com/googleapis/genai-toolbox/internal/sources"
	"github.com/googleapis/genai-toolbox/internal/testutils"
)

func TestBuildTrinoDSN(t *testing.T) {
	tests := []struct {
		name            string
		host            string
		port            string
		user            string
		password        string
		catalog         string
		schema          string
		queryTimeout    string
		accessToken     string
		kerberosEnabled bool
		sslEnabled      bool
		sslCertPath     string
		sslCert         string
		want            string
		wantErr         bool
	}{
		{
			name:    "basic configuration",
			host:    "localhost",
			port:    "8080",
			user:    "testuser",
			catalog: "hive",
			schema:  "default",
			want:    "http://testuser@localhost:8080?catalog=hive&schema=default",
			wantErr: false,
		},
		{
			name:        "with SSL cert path and cert",
			host:        "localhost",
			port:        "8443",
			user:        "testuser",
			catalog:     "hive",
			schema:      "default",
			sslEnabled:  true,
			sslCertPath: "/path/to/cert.pem",
			sslCert:     "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
			want:        "https://testuser@localhost:8443?catalog=hive&schema=default&sslCert=-----BEGIN+CERTIFICATE-----%0A...%0A-----END+CERTIFICATE-----%0A&sslCertPath=%2Fpath%2Fto%2Fcert.pem",
			wantErr:     false,
		},
		{
			name:     "with password",
			host:     "localhost",
			port:     "8080",
			user:     "testuser",
			password: "testpass",
			catalog:  "hive",
			schema:   "default",
			want:     "http://testuser:testpass@localhost:8080?catalog=hive&schema=default",
			wantErr:  false,
		},
		{
			name:       "with SSL",
			host:       "localhost",
			port:       "8443",
			user:       "testuser",
			catalog:    "hive",
			schema:     "default",
			sslEnabled: true,
			want:       "https://testuser@localhost:8443?catalog=hive&schema=default",
			wantErr:    false,
		},
		{
			name:        "with access token",
			host:        "localhost",
			port:        "8080",
			user:        "testuser",
			catalog:     "hive",
			schema:      "default",
			accessToken: "jwt-token-here",
			want:        "http://testuser@localhost:8080?accessToken=jwt-token-here&catalog=hive&schema=default",
			wantErr:     false,
		},
		{
			name:            "with kerberos",
			host:            "localhost",
			port:            "8080",
			user:            "testuser",
			catalog:         "hive",
			schema:          "default",
			kerberosEnabled: true,
			want:            "http://testuser@localhost:8080?KerberosEnabled=true&catalog=hive&schema=default",
			wantErr:         false,
		},
		{
			name:         "with query timeout",
			host:         "localhost",
			port:         "8080",
			user:         "testuser",
			catalog:      "hive",
			schema:       "default",
			queryTimeout: "30m",
			want:         "http://testuser@localhost:8080?catalog=hive&queryTimeout=30m&schema=default",
			wantErr:      false,
		},
		{
			name:    "anonymous access (empty user)",
			host:    "localhost",
			port:    "8080",
			catalog: "hive",
			schema:  "default",
			want:    "http://localhost:8080?catalog=hive&schema=default",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildTrinoDSN(tt.host, tt.port, tt.user, tt.password, tt.catalog, tt.schema, tt.queryTimeout, tt.accessToken, tt.kerberosEnabled, tt.sslEnabled, tt.sslCertPath, tt.sslCert)
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

func TestCheckReadOnly(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckReadOnly(tt.readOnly, tt.statement)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckReadOnly(%v, %q) error = %v, wantErr %v", tt.readOnly, tt.statement, err, tt.wantErr)
			}
		})
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
