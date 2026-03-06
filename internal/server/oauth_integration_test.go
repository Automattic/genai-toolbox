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

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/googleapis/genai-toolbox/internal/log"
	"github.com/googleapis/genai-toolbox/internal/prompts"
	"github.com/googleapis/genai-toolbox/internal/server/mcp/jsonrpc"
	"github.com/googleapis/genai-toolbox/internal/server/oauth"
	"github.com/googleapis/genai-toolbox/internal/server/resources"
	"github.com/googleapis/genai-toolbox/internal/sources"
	"github.com/googleapis/genai-toolbox/internal/telemetry"
	"github.com/googleapis/genai-toolbox/internal/tools"
)

// setUpServerWithOAuth creates a Server with OAuth config and returns the root
// router (with OAuth + MCP routes) and a cleanup func.
func setUpServerWithOAuth(t *testing.T, oauthCfg *oauth.Config, mockTools []MockTool) (chi.Router, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	testLogger, err := log.NewStdLogger(os.Stdout, os.Stderr, "info")
	if err != nil {
		t.Fatalf("unable to initialize logger: %s", err)
	}

	otelShutdown, err := telemetry.SetupOTel(ctx, fakeVersionString, "", false, "toolbox")
	if err != nil {
		t.Fatalf("unable to setup otel: %s", err)
	}

	instrumentation, err := telemetry.CreateTelemetryInstrumentation(fakeVersionString)
	if err != nil {
		t.Fatalf("unable to create custom metrics: %s", err)
	}

	sseManager := newSseManager(ctx)

	toolsMap := make(map[string]tools.Tool)
	var allTools []string
	for _, tool := range mockTools {
		tool.manifest = tool.Manifest()
		toolsMap[tool.Name] = tool
		allTools = append(allTools, tool.Name)
	}
	toolsets := make(map[string]tools.Toolset)
	tc := tools.ToolsetConfig{Name: "", ToolNames: allTools}
	ts, err := tc.Initialize(fakeVersionString, toolsMap)
	if err != nil {
		t.Fatalf("unable to initialize default toolset: %s", err)
	}
	toolsets[""] = ts

	// Create empty promptsets (required by MCP handlers)
	promptsetsMap := make(map[string]prompts.Promptset)
	psc := prompts.PromptsetConfig{Name: ""}
	ps, err := psc.Initialize(fakeVersionString, nil)
	if err != nil {
		t.Fatalf("unable to initialize default promptset: %s", err)
	}
	promptsetsMap[""] = ps

	resourceManager := resources.NewResourceManager(nil, nil, nil, toolsMap, toolsets, nil, promptsetsMap)

	s := &Server{
		version:         fakeVersionString,
		logger:          testLogger,
		instrumentation: instrumentation,
		sseManager:      sseManager,
		ResourceMgr:     resourceManager,
		oauthConfig:     oauthCfg,
	}

	// Build a root router that mirrors NewServer layout
	r := chi.NewRouter()

	// Mount OAuth routes on root
	if oauthCfg != nil {
		oauth.MountRoutes(r, oauthCfg)
	}

	// Mount MCP router under /mcp (includes WWW-Authenticate middleware when oauthConfig is set)
	mcpR, err := mcpRouter(s)
	if err != nil {
		t.Fatalf("unable to initialize mcp router: %s", err)
	}
	r.Mount("/mcp", mcpR)

	shutdown := func() {
		cancel()
		if err := otelShutdown(ctx); err != nil {
			t.Fatalf("error shutting down OpenTelemetry: %s", err)
		}
	}

	return r, shutdown
}

func testOAuthConfig(baseURL string) *oauth.Config {
	return &oauth.Config{
		BaseURL: baseURL,
		Provider: &sources.OAuthConfig{
			AuthorizeEndpoint: "https://looker.example.com/authorize",
			TokenEndpoint:     "https://looker.example.com/api/token",
			ClientID:          "test-client-id",
			Scopes:            []string{"cors_api"},
			VerifySSL:         true,
		},
	}
}

// runMcpInitialize sends the MCP initialize + notifications/initialized handshake
// and returns the session ID (if any). Requests go to /mcp.
func runMcpInitialize(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	initBody := map[string]any{
		"jsonrpc": jsonrpcVersion,
		"id":      "mcp-init",
		"method":  "initialize",
		"params":  map[string]any{"protocolVersion": protocolVersion20250618},
	}
	reqMarshal, _ := json.Marshal(initBody)

	// Include Authorization header so that initialize succeeds when OAuth is
	// configured (the gate requires auth for all methods including initialize).
	initHeader := map[string]string{
		"Authorization": "Bearer init-token",
	}
	resp, _, err := runRequest(ts, http.MethodPost, "/mcp", bytes.NewBuffer(reqMarshal), initHeader)
	if err != nil {
		t.Fatalf("MCP initialize failed: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("MCP initialize: expected 200, got %d", resp.StatusCode)
	}

	// Send initialized notification
	notiBody := map[string]any{
		"jsonrpc": jsonrpcVersion,
		"method":  "notifications/initialized",
	}
	notiMarshal, _ := json.Marshal(notiBody)
	header := map[string]string{
		"MCP-Protocol-Version": protocolVersion20250618,
	}
	_, _, err = runRequest(ts, http.MethodPost, "/mcp", bytes.NewBuffer(notiMarshal), header)
	if err != nil {
		t.Fatalf("MCP initialized notification failed: %s", err)
	}
	return ""
}

func TestOAuthDiscoveryEndpoints(t *testing.T) {
	oauthCfg := testOAuthConfig("http://localhost:5000")
	r, shutdown := setUpServerWithOAuth(t, oauthCfg, []MockTool{tool1})
	defer shutdown()
	ts := httptest.NewServer(r)
	defer ts.Close()

	t.Run("protected resource metadata", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
		if err != nil {
			t.Fatalf("request failed: %s", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %s", err)
		}

		if body["resource"] != "http://localhost:5000/mcp" {
			t.Errorf("unexpected resource: %v", body["resource"])
		}
		authServers, ok := body["authorization_servers"].([]any)
		if !ok || len(authServers) != 1 || authServers[0] != "http://localhost:5000" {
			t.Errorf("unexpected authorization_servers: %v", body["authorization_servers"])
		}
	})

	t.Run("authorization server metadata", func(t *testing.T) {
		resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
		if err != nil {
			t.Fatalf("request failed: %s", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode body: %s", err)
		}

		if body["issuer"] != "http://localhost:5000" {
			t.Errorf("unexpected issuer: %v", body["issuer"])
		}
		if body["authorization_endpoint"] != "http://localhost:5000/authorize" {
			t.Errorf("unexpected authorization_endpoint: %v", body["authorization_endpoint"])
		}
		if body["token_endpoint"] != "http://localhost:5000/token" {
			t.Errorf("unexpected token_endpoint: %v", body["token_endpoint"])
		}
		if body["registration_endpoint"] != "http://localhost:5000/register" {
			t.Errorf("unexpected registration_endpoint: %v", body["registration_endpoint"])
		}
	})
}

func TestOAuthAuthorizeRedirect(t *testing.T) {
	oauthCfg := testOAuthConfig("http://localhost:5000")
	r, shutdown := setUpServerWithOAuth(t, oauthCfg, []MockTool{tool1})
	defer shutdown()
	ts := httptest.NewServer(r)
	defer ts.Close()

	// Don't follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(ts.URL + "/authorize?response_type=code&redirect_uri=http://localhost/callback&resource=http://localhost:5000&code_challenge=abc&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if !strings.HasPrefix(location, "https://looker.example.com/authorize?") {
		t.Errorf("expected redirect to looker.example.com/authorize, got %s", location)
	}
	if strings.Contains(location, "resource=") {
		t.Errorf("resource param should have been stripped from %s", location)
	}
	if !strings.Contains(location, "client_id=test-client-id") {
		t.Errorf("client_id should have been injected in %s", location)
	}
}

func TestOAuthTokenProxy(t *testing.T) {
	// Set up a mock upstream token server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		if strings.Contains(bodyStr, "resource=") {
			t.Error("resource param should have been stripped")
		}
		if !strings.Contains(bodyStr, "client_id=test-client-id") {
			t.Error("client_id should have been injected")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": "looker-access-token",
			"token_type":   "Bearer",
		})
	}))
	defer upstream.Close()

	oauthCfg := &oauth.Config{
		BaseURL: "http://localhost:5000",
		Provider: &sources.OAuthConfig{
			AuthorizeEndpoint: "https://looker.example.com/authorize",
			TokenEndpoint:     upstream.URL,
			ClientID:          "test-client-id",
			Scopes:            []string{"cors_api"},
			VerifySSL:         false,
		},
	}

	r, shutdown := setUpServerWithOAuth(t, oauthCfg, []MockTool{tool1})
	defer shutdown()
	ts := httptest.NewServer(r)
	defer ts.Close()

	resp, err := http.Post(
		ts.URL+"/token",
		"application/x-www-form-urlencoded",
		strings.NewReader("grant_type=authorization_code&code=auth-code-123&resource=http://localhost:5000"),
	)
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %s", err)
	}
	if body["access_token"] != "looker-access-token" {
		t.Errorf("expected access_token looker-access-token, got %s", body["access_token"])
	}
}

func TestOAuthClientRegistration(t *testing.T) {
	oauthCfg := testOAuthConfig("http://localhost:5000")
	r, shutdown := setUpServerWithOAuth(t, oauthCfg, []MockTool{tool1})
	defer shutdown()
	ts := httptest.NewServer(r)
	defer ts.Close()

	reqBody := `{"redirect_uris": ["http://localhost/callback"], "client_name": "claude-code"}`
	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode body: %s", err)
	}
	if body["client_id"] != "test-client-id" {
		t.Errorf("expected client_id test-client-id, got %v", body["client_id"])
	}
	if body["token_endpoint_auth_method"] != "none" {
		t.Errorf("expected auth method none, got %v", body["token_endpoint_auth_method"])
	}
}

func TestMcpWithOAuth_WWWAuthenticateOnUnauthorized(t *testing.T) {
	oauthCfg := testOAuthConfig("http://localhost:5000")
	r, shutdown := setUpServerWithOAuth(t, oauthCfg, []MockTool{tool1})
	defer shutdown()
	ts := httptest.NewServer(r)
	defer ts.Close()

	// The very first MCP request (initialize) without an Authorization header
	// should return 401 with WWW-Authenticate to trigger OAuth discovery.
	reqBody := jsonrpc.JSONRPCRequest{
		Jsonrpc: jsonrpcVersion,
		Id:      "mcp-init-no-auth",
		Request: jsonrpc.Request{
			Method: "initialize",
		},
		Params: map[string]any{
			"protocolVersion": protocolVersion20250618,
		},
	}
	reqMarshal, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("error marshaling request: %s", err)
	}

	resp, body, err := runRequest(ts, http.MethodPost, "/mcp", bytes.NewBuffer(reqMarshal), nil)
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	// Verify WWW-Authenticate header is present (injected by middleware)
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	expectedWWWAuth := `Bearer resource_metadata="http://localhost:5000/.well-known/oauth-protected-resource"`
	if wwwAuth != expectedWWWAuth {
		t.Errorf("expected WWW-Authenticate %q, got %q", expectedWWWAuth, wwwAuth)
	}

	// Verify the JSONRPC error body is still correct
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("error unmarshalling body: %s", err)
	}
	errorObj, ok := got["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in response, got %v", got)
	}
	if errorObj["message"] != "authentication required" {
		t.Errorf("unexpected error message: %v", errorObj["message"])
	}
}

func TestMcpWithOAuth_NoWWWAuthenticateOnSuccess(t *testing.T) {
	oauthCfg := testOAuthConfig("http://localhost:5000")
	r, shutdown := setUpServerWithOAuth(t, oauthCfg, []MockTool{tool1})
	defer shutdown()
	ts := httptest.NewServer(r)
	defer ts.Close()

	runMcpInitialize(t, ts)

	// tool1 doesn't require tool-level auth, so the call should succeed without WWW-Authenticate.
	// An Authorization header is still required at the gate level when OAuth is configured.
	reqBody := jsonrpc.JSONRPCRequest{
		Jsonrpc: jsonrpcVersion,
		Id:      "tools-call-public",
		Request: jsonrpc.Request{
			Method: "tools/call",
		},
		Params: map[string]any{
			"name": "no_params",
		},
	}
	reqMarshal, _ := json.Marshal(reqBody)

	header := map[string]string{
		"MCP-Protocol-Version": protocolVersion20250618,
		"Authorization":        "Bearer some-token",
	}
	resp, _, err := runRequest(ts, http.MethodPost, "/mcp", bytes.NewBuffer(reqMarshal), header)
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth != "" {
		t.Errorf("expected no WWW-Authenticate on success, got %q", wwwAuth)
	}
}

func TestMcpWithOAuth_ToolsListRequiresAuth(t *testing.T) {
	oauthCfg := testOAuthConfig("http://localhost:5000")
	r, shutdown := setUpServerWithOAuth(t, oauthCfg, []MockTool{tool1})
	defer shutdown()
	ts := httptest.NewServer(r)
	defer ts.Close()

	runMcpInitialize(t, ts)

	reqBody := jsonrpc.JSONRPCRequest{
		Jsonrpc: jsonrpcVersion,
		Id:      "tools-list-no-auth",
		Request: jsonrpc.Request{
			Method: "tools/list",
		},
	}
	reqMarshal, _ := json.Marshal(reqBody)

	header := map[string]string{
		"MCP-Protocol-Version": protocolVersion20250618,
	}

	// Without Authorization header, should get 401
	resp, body, err := runRequest(ts, http.MethodPost, "/mcp", bytes.NewBuffer(reqMarshal), header)
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", resp.StatusCode)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "oauth-protected-resource") {
		t.Errorf("expected WWW-Authenticate header, got %q", wwwAuth)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("error unmarshalling body: %s", err)
	}
	errorObj, ok := got["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", got)
	}
	if errorObj["message"] != "authentication required" {
		t.Errorf("unexpected error message: %v", errorObj["message"])
	}

	// With Authorization header, should succeed
	headerWithAuth := map[string]string{
		"MCP-Protocol-Version": protocolVersion20250618,
		"Authorization":        "Bearer some-token",
	}
	reqMarshal2, _ := json.Marshal(reqBody)
	resp2, _, err := runRequest(ts, http.MethodPost, "/mcp", bytes.NewBuffer(reqMarshal2), headerWithAuth)
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with auth, got %d", resp2.StatusCode)
	}
}

func TestMcpWithOAuth_SseNotHardBlocked(t *testing.T) {
	oauthCfg := testOAuthConfig("http://localhost:5000")
	r, shutdown := setUpServerWithOAuth(t, oauthCfg, []MockTool{tool1})
	defer shutdown()
	ts := httptest.NewServer(r)
	defer ts.Close()

	// SSE connection should still establish without Authorization header
	resp, err := http.Get(ts.URL + "/mcp/sse")
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}
	defer resp.Body.Close()

	// Should get 200 with event stream, NOT 401
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected SSE to return 200 (not hard-blocked), got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/event-stream") {
		t.Errorf("expected Content-Type text/event-stream, got %s", contentType)
	}
}

func TestMcpWithoutOAuth_NoWWWAuthenticateOnUnauthorized(t *testing.T) {
	// No OAuth config -- 401 responses should NOT have WWW-Authenticate
	r, shutdown := setUpServerWithOAuth(t, nil, []MockTool{tool1, tool5})
	defer shutdown()
	ts := httptest.NewServer(r)
	defer ts.Close()

	runMcpInitialize(t, ts)

	reqBody := jsonrpc.JSONRPCRequest{
		Jsonrpc: jsonrpcVersion,
		Id:      "tools-call-no-oauth",
		Request: jsonrpc.Request{
			Method: "tools/call",
		},
		Params: map[string]any{
			"name": "require_client_auth_tool",
		},
	}
	reqMarshal, _ := json.Marshal(reqBody)

	header := map[string]string{
		"MCP-Protocol-Version": protocolVersion20250618,
	}
	resp, _, err := runRequest(ts, http.MethodPost, "/mcp", bytes.NewBuffer(reqMarshal), header)
	if err != nil {
		t.Fatalf("request failed: %s", err)
	}

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth != "" {
		t.Errorf("expected no WWW-Authenticate without OAuth config, got %q", wwwAuth)
	}
}

func TestOAuthFullDiscoveryFlow(t *testing.T) {
	// Simulates the full MCP OAuth discovery sequence:
	// 1. Client hits MCP endpoint, gets 401 with WWW-Authenticate
	// 2. Client fetches protected resource metadata
	// 3. Client fetches authorization server metadata
	// 4. Client calls /register
	// 5. Client redirected via /authorize
	// 6. Client exchanges code via /token

	// Mock upstream token server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token":  "final-access-token",
			"token_type":    "Bearer",
			"refresh_token": "refresh-123",
		})
	}))
	defer upstream.Close()

	oauthCfg := &oauth.Config{
		BaseURL: "http://localhost:5000",
		Provider: &sources.OAuthConfig{
			AuthorizeEndpoint: "https://looker.example.com/authorize",
			TokenEndpoint:     upstream.URL,
			ClientID:          "test-client-id",
			Scopes:            []string{"cors_api"},
			VerifySSL:         false,
		},
	}

	r, shutdown := setUpServerWithOAuth(t, oauthCfg, []MockTool{tool1, tool5})
	defer shutdown()
	ts := httptest.NewServer(r)
	defer ts.Close()

	// Step 1: First MCP request (initialize) without auth -- get 401 with discovery hint
	reqBody := jsonrpc.JSONRPCRequest{
		Jsonrpc: jsonrpcVersion,
		Id:      "step1",
		Request: jsonrpc.Request{Method: "initialize"},
		Params:  map[string]any{"protocolVersion": protocolVersion20250618},
	}
	reqMarshal, _ := json.Marshal(reqBody)
	resp, _, err := runRequest(ts, http.MethodPost, "/mcp", bytes.NewBuffer(reqMarshal), nil)
	if err != nil {
		t.Fatalf("step 1 failed: %s", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("step 1: expected 401, got %d", resp.StatusCode)
	}
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "/.well-known/oauth-protected-resource") {
		t.Fatalf("step 1: WWW-Authenticate missing resource_metadata: %q", wwwAuth)
	}

	// Step 2: Fetch protected resource metadata
	resp2, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("step 2 failed: %s", err)
	}
	var protectedResource map[string]any
	json.NewDecoder(resp2.Body).Decode(&protectedResource)
	resp2.Body.Close()

	authServers := protectedResource["authorization_servers"].([]any)
	authServerURL := authServers[0].(string)

	// Step 3: Fetch authorization server metadata
	resp3, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("step 3 failed: %s", err)
	}
	var authServerMeta map[string]any
	json.NewDecoder(resp3.Body).Decode(&authServerMeta)
	resp3.Body.Close()

	if authServerMeta["issuer"] != authServerURL {
		t.Errorf("step 3: issuer mismatch: %v vs %v", authServerMeta["issuer"], authServerURL)
	}
	registrationEndpoint := authServerMeta["registration_endpoint"].(string)
	tokenEndpoint := authServerMeta["token_endpoint"].(string)
	authorizeEndpoint := authServerMeta["authorization_endpoint"].(string)

	// Step 4: Register client
	regReqBody := `{"redirect_uris": ["http://localhost/callback"], "client_name": "claude-code"}`
	resp4, err := http.Post(
		// Use ts.URL prefix since the metadata returns the configured baseURL, not the test server URL
		strings.Replace(registrationEndpoint, "http://localhost:5000", ts.URL, 1),
		"application/json",
		strings.NewReader(regReqBody),
	)
	if err != nil {
		t.Fatalf("step 4 failed: %s", err)
	}
	var regResponse map[string]any
	json.NewDecoder(resp4.Body).Decode(&regResponse)
	resp4.Body.Close()

	clientID := regResponse["client_id"].(string)
	if clientID != "test-client-id" {
		t.Errorf("step 4: unexpected client_id: %s", clientID)
	}

	// Step 5: Authorize redirect
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authorizeURL := strings.Replace(authorizeEndpoint, "http://localhost:5000", ts.URL, 1)
	resp5, err := noRedirectClient.Get(
		fmt.Sprintf("%s?response_type=code&redirect_uri=http://localhost/callback&code_challenge=abc&code_challenge_method=S256", authorizeURL),
	)
	if err != nil {
		t.Fatalf("step 5 failed: %s", err)
	}
	resp5.Body.Close()

	if resp5.StatusCode != http.StatusFound {
		t.Fatalf("step 5: expected 302, got %d", resp5.StatusCode)
	}
	location := resp5.Header.Get("Location")
	if !strings.Contains(location, "looker.example.com/authorize") {
		t.Errorf("step 5: expected redirect to looker, got %s", location)
	}

	// Step 6: Exchange code for token
	tokenURL := strings.Replace(tokenEndpoint, "http://localhost:5000", ts.URL, 1)
	resp6, err := http.Post(
		tokenURL,
		"application/x-www-form-urlencoded",
		strings.NewReader("grant_type=authorization_code&code=test-auth-code&redirect_uri=http://localhost/callback"),
	)
	if err != nil {
		t.Fatalf("step 6 failed: %s", err)
	}
	var tokenResponse map[string]string
	json.NewDecoder(resp6.Body).Decode(&tokenResponse)
	resp6.Body.Close()

	if tokenResponse["access_token"] != "final-access-token" {
		t.Errorf("step 6: unexpected access_token: %s", tokenResponse["access_token"])
	}
	if tokenResponse["refresh_token"] != "refresh-123" {
		t.Errorf("step 6: unexpected refresh_token: %s", tokenResponse["refresh_token"])
	}
}
