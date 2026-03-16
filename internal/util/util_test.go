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

package util

import (
	"context"
	"net/http"
	"testing"
)

func TestWithRequestHeaders_StripsSensitiveHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer secret")
	h.Set("Cookie", "session=abc")
	h.Set("Proxy-Authorization", "Basic creds")
	h.Set("Set-Cookie", "foo=bar")
	h.Set("X-Client-Tags", "claude-code")
	h.Set("X-Request-Id", "123")

	ctx := WithRequestHeaders(context.Background(), h)
	got := RequestHeadersFromContext(ctx)

	if got.Get("Authorization") != "" {
		t.Error("Authorization header should be stripped")
	}
	if got.Get("Cookie") != "" {
		t.Error("Cookie header should be stripped")
	}
	if got.Get("Proxy-Authorization") != "" {
		t.Error("Proxy-Authorization header should be stripped")
	}
	if got.Get("Set-Cookie") != "" {
		t.Error("Set-Cookie header should be stripped")
	}
	if got.Get("X-Client-Tags") != "claude-code" {
		t.Errorf("X-Client-Tags = %q, want %q", got.Get("X-Client-Tags"), "claude-code")
	}
	if got.Get("X-Request-Id") != "123" {
		t.Errorf("X-Request-Id = %q, want %q", got.Get("X-Request-Id"), "123")
	}

	// Original header must not be mutated.
	if h.Get("Authorization") != "Bearer secret" {
		t.Error("original Authorization header was mutated")
	}
}

func TestWithRequestHeaders_StripsExtraSensitiveHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("X-Authenticated-User", "alice")
	h.Set("X-Client-Tags", "claude-code")

	ctx := WithRequestHeaders(context.Background(), h, "X-Authenticated-User")
	got := RequestHeadersFromContext(ctx)

	if got.Get("X-Authenticated-User") != "" {
		t.Error("extra sensitive header X-Authenticated-User should be stripped")
	}
	if got.Get("X-Client-Tags") != "claude-code" {
		t.Errorf("X-Client-Tags = %q, want %q", got.Get("X-Client-Tags"), "claude-code")
	}
}

func TestWithRequestHeaders_NilReturnsUnmodifiedContext(t *testing.T) {
	ctx := context.Background()
	got := WithRequestHeaders(ctx, nil)
	if RequestHeadersFromContext(got) != nil {
		t.Error("nil header input should not store anything in context")
	}
}
