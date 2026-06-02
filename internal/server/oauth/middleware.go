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
	"fmt"
	"net/http"
)

// WWWAuthenticateMiddleware intercepts 401 responses and injects the
// WWW-Authenticate header pointing to the OAuth protected resource metadata.
func WWWAuthenticateMiddleware(baseURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(&responseInterceptor{ResponseWriter: w, baseURL: baseURL}, r)
		})
	}
}

// responseInterceptor wraps http.ResponseWriter to inject WWW-Authenticate on 401.
type responseInterceptor struct {
	http.ResponseWriter
	baseURL string
}

func (ri *responseInterceptor) WriteHeader(code int) {
	if code == http.StatusUnauthorized {
		ri.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, ri.baseURL))
	}
	ri.ResponseWriter.WriteHeader(code)
}

// Flush delegates to the underlying writer if it implements http.Flusher.
// This is required for SSE streaming to work through the middleware.
func (ri *responseInterceptor) Flush() {
	if f, ok := ri.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap returns the underlying ResponseWriter, allowing middleware like
// chi's to discover interfaces (http.Flusher, http.Hijacker, etc.) on the
// original writer.
func (ri *responseInterceptor) Unwrap() http.ResponseWriter {
	return ri.ResponseWriter
}
