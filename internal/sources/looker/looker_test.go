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

package looker_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	toolboxlog "github.com/googleapis/mcp-toolbox/internal/log"
	"github.com/googleapis/mcp-toolbox/internal/server"
	"github.com/googleapis/mcp-toolbox/internal/sources"
	"github.com/googleapis/mcp-toolbox/internal/sources/looker"
	"github.com/googleapis/mcp-toolbox/internal/testutils"
	"github.com/googleapis/mcp-toolbox/internal/util"
	"github.com/looker-open-source/sdk-codegen/go/rtl"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestParseFromYamlLooker(t *testing.T) {
	tcs := []struct {
		desc string
		in   string
		want server.SourceConfigs
	}{
		{
			desc: "basic example",
			in: `
			kind: source
			name: my-looker-instance
			type: looker
			base_url: http://example.looker.com/
			client_id: jasdl;k;tjl
			client_secret: sdakl;jgflkasdfkfg
			`,
			want: map[string]sources.SourceConfig{
				"my-looker-instance": looker.Config{
					Name:               "my-looker-instance",
					Type:               looker.SourceType,
					BaseURL:            "http://example.looker.com/",
					ClientId:           "jasdl;k;tjl",
					ClientSecret:       "sdakl;jgflkasdfkfg",
					Timeout:            "600s",
					SslVerification:    true,
					UseClientOAuth:     "false",
					ShowHiddenModels:   true,
					ShowHiddenExplores: true,
					ShowHiddenFields:   true,
					Location:           "us",
					SessionLength:      1200,
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

func TestFailParseFromYaml(t *testing.T) {
	tcs := []struct {
		desc string
		in   string
		err  string
	}{
		{
			desc: "extra field",
			in: `
			kind: source
			name: my-looker-instance
			type: looker
			base_url: http://example.looker.com/
			client_id: jasdl;k;tjl
			client_secret: sdakl;jgflkasdfkfg
			schema: test-schema
			`,
			err: "error unmarshaling source: unable to parse source \"my-looker-instance\" as \"looker\": [5:1] unknown field \"schema\"\n   2 | client_id: jasdl;k;tjl\n   3 | client_secret: sdakl;jgflkasdfkfg\n   4 | name: my-looker-instance\n>  5 | schema: test-schema\n       ^\n   6 | type: looker",
		},
		{
			desc: "missing required field",
			in: `
			kind: source
			name: my-looker-instance
			type: looker
			client_id: jasdl;k;tjl
			`,
			err: "error unmarshaling source: unable to parse source \"my-looker-instance\" as \"looker\": Key: 'Config.BaseURL' Error:Field validation for 'BaseURL' failed on the 'required' tag",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.desc, func(t *testing.T) {
			_, _, _, _, _, _, err := server.UnmarshalResourceConfig(context.Background(), testutils.FormatYaml(tc.in))
			if err == nil {
				t.Fatalf("expect parsing to fail")
			}
			errStr := err.Error()
			if errStr != tc.err {
				t.Fatalf("unexpected error: got %q, want %q", errStr, tc.err)
			}
		})
	}
}

func TestValidateOAuthTokenForwardsBearerHeader(t *testing.T) {
	var mu sync.Mutex
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if a := r.Header.Get("Authorization"); a != "" {
			gotAuth = a
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"1"}`))
	}))
	t.Cleanup(ts.Close)

	s := &looker.Source{
		Config: looker.Config{
			Name:           "t",
			BaseURL:        ts.URL,
			UseClientOAuth: "true",
		},
		ApiSettings: &rtl.ApiSettings{
			BaseUrl:    ts.URL,
			ApiVersion: "4.0",
			VerifySsl:  false,
			Timeout:    30,
		},
	}

	if err := s.ValidateOAuthToken(context.Background(), "Bearer abc123"); err != nil {
		t.Fatalf("ValidateOAuthToken returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "Bearer abc123" {
		t.Errorf("Authorization header sent to Looker = %q, want %q (the full Bearer header must be forwarded)", gotAuth, "Bearer abc123")
	}
}

func TestInitializeOAuthProxyValidation(t *testing.T) {
	ctx, err := testutils.ContextWithNewLogger()
	if err != nil {
		t.Fatalf("unable to create context: %s", err)
	}
	ctx = util.WithUserAgent(ctx, "test-agent")
	tracer := noop.NewTracerProvider().Tracer("")

	cases := []struct {
		name      string
		cfg       looker.Config
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "proxy with use_client_oauth true is valid",
			cfg:     looker.Config{Name: "l", Type: "looker", BaseURL: "https://looker.example.com", Timeout: "600s", UseClientOAuth: "true", OAuthBaseURL: "https://looker.example.com", OAuthClientID: "mcp"},
			wantErr: false,
		},
		{
			name:      "proxy without client_id is rejected",
			cfg:       looker.Config{Name: "l", Type: "looker", BaseURL: "https://looker.example.com", Timeout: "600s", UseClientOAuth: "true", OAuthBaseURL: "https://looker.example.com"},
			wantErr:   true,
			errSubstr: "oauth_client_id is required",
		},
		{
			name:      "proxy with custom auth header is rejected",
			cfg:       looker.Config{Name: "l", Type: "looker", BaseURL: "https://looker.example.com", Timeout: "600s", UseClientOAuth: "X-Looker-Auth", OAuthBaseURL: "https://looker.example.com", OAuthClientID: "mcp"},
			wantErr:   true,
			errSubstr: "use_client_oauth: 'true'",
		},
		{
			name:      "proxy with disabled client oauth is rejected",
			cfg:       looker.Config{Name: "l", Type: "looker", BaseURL: "https://looker.example.com", Timeout: "600s", UseClientOAuth: "false", OAuthBaseURL: "https://looker.example.com", OAuthClientID: "mcp"},
			wantErr:   true,
			errSubstr: "use_client_oauth: 'true'",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.cfg.Initialize(ctx, tracer)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestOAuthProviderConfigScopes(t *testing.T) {
	cases := []struct {
		name   string
		scopes string
		want   []string
	}{
		{name: "empty defaults to cors_api", scopes: "", want: []string{"cors_api"}},
		{name: "comma-separated with spaces", scopes: "cors_api, all_access ,foo", want: []string{"cors_api", "all_access", "foo"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &looker.Source{Config: looker.Config{
				BaseURL:        "https://looker.example.com",
				UseClientOAuth: "true",
				OAuthBaseURL:   "https://looker.example.com",
				OAuthClientID:  "mcp",
				OAuthScopes:    tc.scopes,
			}}
			pc := s.OAuthProviderConfig()
			if pc == nil {
				t.Fatal("expected non-nil OAuthConfig")
			}
			if !cmp.Equal(pc.Scopes, tc.want) {
				t.Errorf("scopes = %v, want %v", pc.Scopes, tc.want)
			}
		})
	}
}

func TestUseClientAuthorization(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"   ", false},
		{"false", false},
		{"False", false},
		{"true", true},
		{"True", true},
		{"X-Looker-Auth", true},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			s := &looker.Source{Config: looker.Config{UseClientOAuth: tc.value}}
			if got := s.UseClientAuthorization(); got != tc.want {
				t.Errorf("UseClientAuthorization(%q) = %v, want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestGetLookerSDK_ClientIPPropagation(t *testing.T) {
	// 1. Start a local test server
	serverReceivedHeaders := make(http.Header)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for k, v := range r.Header {
			serverReceivedHeaders[k] = v
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"id": 123}`)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
	defer ts.Close()

	// 2. Construct looker Config with UseClientOAuth = "true" pointing to the local test server
	cfg := looker.Config{
		Name:            "test-looker",
		Type:            "looker",
		BaseURL:         ts.URL,
		UseClientOAuth:  "true",
		Timeout:         "5s",
		SslVerification: false,
	}

	// 3. Initialize the source
	ctx := context.Background()
	// Inject a logger so Initialize doesn't fail
	logger, err := toolboxlog.NewStdLogger(io.Discard, io.Discard, "DEBUG")
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	ctx = util.WithLogger(ctx, logger)
	ctx = util.WithUserAgent(ctx, "test-agent")

	src, err := cfg.Initialize(ctx, nil)
	if err != nil {
		t.Fatalf("failed to initialize source: %v", err)
	}

	lookerSrc, ok := src.(*looker.Source)
	if !ok {
		t.Fatalf("source is not of type *looker.Source")
	}

	// 4. Inject Client IP into the context
	testIP := "203.0.113.195"
	ctxWithIP := util.WithClientIP(ctx, testIP)

	// 5. Retrieve the Looker SDK using GetLookerSDK
	sdk, err := lookerSrc.GetLookerSDK(ctxWithIP, "mock-token-123")
	if err != nil {
		t.Fatalf("GetLookerSDK failed: %v", err)
	}

	// 6. Retrieve session and request a call using the session client
	authSession, ok := sdk.AuthSession.(*rtl.AuthSession)
	if !ok {
		t.Fatalf("SDK session is not *rtl.AuthSession")
	}

	client := authSession.Client
	req, err := http.NewRequestWithContext(ctxWithIP, "GET", ts.URL+"/api/4.0/user", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// 7. Assert headers are correctly propagated to the test server
	if gotIP := serverReceivedHeaders.Get("X-Forwarded-For"); gotIP != testIP {
		t.Errorf("expected X-Forwarded-For to be %q, got %q", testIP, gotIP)
	}
	if gotIP := serverReceivedHeaders.Get("X-Real-IP"); gotIP != testIP {
		t.Errorf("expected X-Real-IP to be %q, got %q", testIP, gotIP)
	}
	if gotAuth := serverReceivedHeaders.Get("Authorization"); gotAuth != "mock-token-123" {
		t.Errorf("expected Authorization header to be %q, got %q", "mock-token-123", gotAuth)
	}
}
