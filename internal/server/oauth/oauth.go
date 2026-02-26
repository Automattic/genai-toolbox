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
	"github.com/go-chi/chi/v5"
	"github.com/googleapis/genai-toolbox/internal/sources"
)

// Config holds the server-level OAuth proxy configuration.
type Config struct {
	BaseURL  string              // external URL of this toolbox server
	Provider *sources.OAuthConfig // from the source that implements OAuthProvider
}

// MountRoutes mounts OAuth discovery and proxy endpoints on the given router.
func MountRoutes(r chi.Router, cfg *Config) {
	r.Get("/.well-known/oauth-protected-resource", protectedResourceHandler(cfg))
	r.Get("/.well-known/oauth-authorization-server", authServerMetadataHandler(cfg))
	r.Get("/authorize", authorizeHandler(cfg))
	r.Post("/token", tokenHandler(cfg))
	r.Post("/register", registerHandler(cfg))
}
