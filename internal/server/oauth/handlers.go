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
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// protectedResourceHandler returns RFC 9728 protected resource metadata.
// GET /.well-known/oauth-protected-resource
func protectedResourceHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]any{
			"resource":                cfg.BaseURL + "/mcp",
			"authorization_servers":   []string{cfg.BaseURL},
			"bearer_methods_supported": []string{"header"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}
}

// authServerMetadataHandler returns RFC 8414 authorization server metadata.
// GET /.well-known/oauth-authorization-server
func authServerMetadataHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]any{
			"issuer":                                cfg.BaseURL,
			"authorization_endpoint":                cfg.BaseURL + "/authorize",
			"token_endpoint":                        cfg.BaseURL + "/token",
			"registration_endpoint":                 cfg.BaseURL + "/register",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"token_endpoint_auth_methods_supported": []string{"none"},
			"scopes_supported":                      cfg.Provider.Scopes,
			"code_challenge_methods_supported":      []string{"S256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}
}

// authorizeHandler proxies authorization requests to the upstream OAuth provider.
// GET /authorize
// Strips the `resource` param, injects `client_id`, and 302-redirects to the upstream.
func authorizeHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		upstreamURL, err := url.Parse(cfg.Provider.AuthorizeEndpoint)
		if err != nil {
			http.Error(w, "invalid authorize URL configuration", http.StatusInternalServerError)
			return
		}

		params := r.URL.Query()
		params.Del("resource")
		params.Set("client_id", cfg.Provider.ClientID)
		if len(cfg.Provider.Scopes) > 0 && params.Get("scope") == "" {
			params.Set("scope", strings.Join(cfg.Provider.Scopes, " "))
		}
		upstreamURL.RawQuery = params.Encode()

		http.Redirect(w, r, upstreamURL.String(), http.StatusFound)
	}
}

// tokenHandler proxies token exchange requests to the upstream OAuth provider.
// POST /token
// Strips the `resource` param, injects `client_id` (and `client_secret` for
// confidential clients), and proxies to the upstream token endpoint.
func tokenHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}

		params := r.PostForm
		params.Del("resource")
		params.Set("client_id", cfg.Provider.ClientID)
		if cfg.Provider.ClientSecret != "" {
			params.Set("client_secret", cfg.Provider.ClientSecret)
		}

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !cfg.Provider.VerifySSL,
			},
		}
		client := &http.Client{Transport: transport}

		resp, err := client.Post(cfg.Provider.TokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(params.Encode()))
		if err != nil {
			http.Error(w, "token exchange failed", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}
}

// registerHandler implements dynamic client registration.
// POST /register
// Returns the pre-configured client metadata since the client is already registered with
// the upstream provider.
func registerHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var requestBody map[string]any
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		redirectURIs, _ := requestBody["redirect_uris"]

		responseBody := map[string]any{
			"client_id":                  cfg.Provider.ClientID,
			"client_secret":              "",
			"redirect_uris":              redirectURIs,
			"grant_types":                []string{"authorization_code", "refresh_token"},
			"response_types":             []string{"code"},
			"token_endpoint_auth_method": "none",
			"scope":                      strings.Join(cfg.Provider.Scopes, " "),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(responseBody)
	}
}
