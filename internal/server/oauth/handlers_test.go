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

package oauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/googleapis/genai-toolbox/internal/sources"
)

func testPublicConfig() *Config {
	return &Config{
		BaseURL: "http://localhost:5000",
		Provider: &sources.OAuthConfig{
			AuthorizeEndpoint: "https://looker.example.com/authorize",
			TokenEndpoint:     "https://looker.example.com/api/token",
			ClientID:          "test-client-id",
			Scopes:            []string{"cors_api"},
			VerifySSL:         true,
		},
	}
}

func testConfidentialConfig() *Config {
	return &Config{
		BaseURL: "http://localhost:5000",
		Provider: &sources.OAuthConfig{
			AuthorizeEndpoint: "https://looker.example.com/authorize",
			TokenEndpoint:     "https://looker.example.com/api/token",
			ClientID:          "test-client-id",
			ClientSecret:      "test-client-secret",
			Scopes:            []string{"cors_api"},
			VerifySSL:         true,
		},
	}
}

func TestProtectedResourceHandler(t *testing.T) {
	cfg := testPublicConfig()
	handler := protectedResourceHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}

	if body["resource"] != "http://localhost:5000" {
		t.Errorf("expected resource http://localhost:5000, got %v", body["resource"])
	}

	authServers, ok := body["authorization_servers"].([]any)
	if !ok || len(authServers) != 1 || authServers[0] != "http://localhost:5000" {
		t.Errorf("unexpected authorization_servers: %v", body["authorization_servers"])
	}
}

func TestAuthServerMetadataHandler(t *testing.T) {
	t.Run("public client", func(t *testing.T) {
		cfg := testPublicConfig()
		handler := authServerMetadataHandler(cfg)

		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}

		if body["issuer"] != "http://localhost:5000" {
			t.Errorf("expected issuer http://localhost:5000, got %v", body["issuer"])
		}
		if body["authorization_endpoint"] != "http://localhost:5000/authorize" {
			t.Errorf("unexpected authorization_endpoint: %v", body["authorization_endpoint"])
		}

		authMethods, ok := body["token_endpoint_auth_methods_supported"].([]any)
		if !ok || len(authMethods) != 1 || authMethods[0] != "none" {
			t.Errorf("expected auth method 'none' for public client, got %v", body["token_endpoint_auth_methods_supported"])
		}
	})

	t.Run("confidential client", func(t *testing.T) {
		cfg := testConfidentialConfig()
		handler := authServerMetadataHandler(cfg)

		req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}

		authMethods, ok := body["token_endpoint_auth_methods_supported"].([]any)
		if !ok || len(authMethods) != 1 || authMethods[0] != "client_secret_post" {
			t.Errorf("expected auth method 'client_secret_post' for confidential client, got %v", body["token_endpoint_auth_methods_supported"])
		}
	})
}

func TestAuthorizeHandler(t *testing.T) {
	cfg := testPublicConfig()
	handler := authorizeHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&redirect_uri=http://localhost/callback&resource=http://localhost:5000&code_challenge=abc&code_challenge_method=S256", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("expected status 302, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	// Should redirect to the upstream authorize endpoint directly (no path appended)
	if !strings.HasPrefix(location, "https://looker.example.com/authorize?") {
		t.Errorf("expected redirect to looker.example.com/authorize, got %s", location)
	}
	if strings.Contains(location, "resource=") {
		t.Errorf("expected resource param to be stripped, but found in %s", location)
	}
	if !strings.Contains(location, "client_id=test-client-id") {
		t.Errorf("expected client_id to be injected, not found in %s", location)
	}
	if !strings.Contains(location, "response_type=code") {
		t.Errorf("expected response_type=code to be preserved, not found in %s", location)
	}
}

func TestTokenHandler(t *testing.T) {
	t.Run("public client", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			bodyStr := string(body)

			if strings.Contains(bodyStr, "resource=") {
				t.Error("resource param should have been stripped")
			}
			if !strings.Contains(bodyStr, "client_id=test-client-id") {
				t.Error("client_id should have been injected")
			}
			if strings.Contains(bodyStr, "client_secret=") {
				t.Error("client_secret should not be present for public client")
			}
			if !strings.Contains(bodyStr, "code=auth-code-123") {
				t.Error("code param should have been preserved")
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
			})
		}))
		defer upstream.Close()

		cfg := &Config{
			BaseURL: "http://localhost:5000",
			Provider: &sources.OAuthConfig{
				AuthorizeEndpoint: "https://looker.example.com/authorize",
				TokenEndpoint:     upstream.URL,
				ClientID:          "test-client-id",
				Scopes:            []string{"cors_api"},
				VerifySSL:         false,
			},
		}

		handler := tokenHandler(cfg)

		req := httptest.NewRequest(http.MethodPost, "/token",
			strings.NewReader("grant_type=authorization_code&code=auth-code-123&resource=http://localhost:5000"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		var body map[string]string
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}
		if body["access_token"] != "test-access-token" {
			t.Errorf("expected access_token test-access-token, got %s", body["access_token"])
		}
	})

	t.Run("confidential client forwards secret", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			bodyStr := string(body)

			if !strings.Contains(bodyStr, "client_secret=test-client-secret") {
				t.Error("client_secret should have been injected for confidential client")
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "confidential-token",
				"token_type":   "Bearer",
			})
		}))
		defer upstream.Close()

		cfg := &Config{
			BaseURL: "http://localhost:5000",
			Provider: &sources.OAuthConfig{
				AuthorizeEndpoint: "https://looker.example.com/authorize",
				TokenEndpoint:     upstream.URL,
				ClientID:          "test-client-id",
				ClientSecret:      "test-client-secret",
				Scopes:            []string{"cors_api"},
				VerifySSL:         false,
			},
		}

		handler := tokenHandler(cfg)

		req := httptest.NewRequest(http.MethodPost, "/token",
			strings.NewReader("grant_type=authorization_code&code=auth-code-123"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}
	})
}

func TestRegisterHandler(t *testing.T) {
	t.Run("public client", func(t *testing.T) {
		cfg := testPublicConfig()
		handler := registerHandler(cfg)

		reqBody := `{"redirect_uris": ["http://localhost/callback"], "client_name": "test"}`
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("expected status 201, got %d", rr.Code)
		}

		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}

		if body["client_id"] != "test-client-id" {
			t.Errorf("expected client_id test-client-id, got %v", body["client_id"])
		}
		if body["token_endpoint_auth_method"] != "none" {
			t.Errorf("expected token_endpoint_auth_method none, got %v", body["token_endpoint_auth_method"])
		}
		if body["client_secret"] != "" {
			t.Errorf("expected empty client_secret for public client, got %v", body["client_secret"])
		}
	})

	t.Run("confidential client", func(t *testing.T) {
		cfg := testConfidentialConfig()
		handler := registerHandler(cfg)

		reqBody := `{"redirect_uris": ["http://localhost/callback"]}`
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("expected status 201, got %d", rr.Code)
		}

		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}

		if body["token_endpoint_auth_method"] != "client_secret_post" {
			t.Errorf("expected token_endpoint_auth_method client_secret_post, got %v", body["token_endpoint_auth_method"])
		}
		if body["client_secret"] != "test-client-secret" {
			t.Errorf("expected client_secret test-client-secret, got %v", body["client_secret"])
		}
	})
}

func TestWWWAuthenticateMiddleware(t *testing.T) {
	baseURL := "http://localhost:5000"
	mw := WWWAuthenticateMiddleware(baseURL)

	t.Run("injects header on 401", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		mw(inner).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rr.Code)
		}

		wwwAuth := rr.Header().Get("WWW-Authenticate")
		expected := `Bearer resource_metadata="http://localhost:5000/.well-known/oauth-protected-resource"`
		if wwwAuth != expected {
			t.Errorf("expected WWW-Authenticate %q, got %q", expected, wwwAuth)
		}
	})

	t.Run("does not inject header on 200", func(t *testing.T) {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rr := httptest.NewRecorder()
		mw(inner).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		wwwAuth := rr.Header().Get("WWW-Authenticate")
		if wwwAuth != "" {
			t.Errorf("expected no WWW-Authenticate header, got %q", wwwAuth)
		}
	})
}

func TestMountRoutes(t *testing.T) {
	cfg := testPublicConfig()
	r := chi.NewRouter()
	MountRoutes(r, cfg)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/.well-known/oauth-protected-resource"},
		{http.MethodGet, "/.well-known/oauth-authorization-server"},
		{http.MethodGet, "/authorize"},
		{http.MethodPost, "/token"},
		{http.MethodPost, "/register"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		if rr.Code == http.StatusNotFound || rr.Code == http.StatusMethodNotAllowed {
			t.Errorf("route %s %s returned %d, expected it to be mounted", route.method, route.path, rr.Code)
		}
	}
}
