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

package trinosql

import (
	"context"
	"testing"

	"github.com/googleapis/genai-toolbox/internal/sources"
	"github.com/googleapis/genai-toolbox/internal/tools"
	"github.com/googleapis/genai-toolbox/internal/util/parameters"
)

// mockTrinoSource implements both sources.Source and the compatibleSource
// interface so it can be returned by the mock SourceProvider and cast
// successfully inside GetCompatibleSource.
type mockTrinoSource struct {
	useClientAuth      bool
	authHeaderName     string
	runSQLCalled       bool
	runSQLAsUserCalled bool
	lastStatement      string
	lastParams         []any
	lastUser           string
	returnValue        any
	returnErr          error
}

func (m *mockTrinoSource) SourceType() string             { return "trino" }
func (m *mockTrinoSource) ToConfig() sources.SourceConfig { return nil }
func (m *mockTrinoSource) UseClientAuthorization() bool   { return m.useClientAuth }
func (m *mockTrinoSource) GetAuthTokenHeaderName() string { return m.authHeaderName }

func (m *mockTrinoSource) RunSQL(ctx context.Context, stmt string, params []any) (any, error) {
	m.runSQLCalled = true
	m.lastStatement = stmt
	m.lastParams = params
	return m.returnValue, m.returnErr
}

func (m *mockTrinoSource) RunSQLAsUser(ctx context.Context, stmt string, params []any, user string) (any, error) {
	m.runSQLAsUserCalled = true
	m.lastStatement = stmt
	m.lastParams = params
	m.lastUser = user
	return m.returnValue, m.returnErr
}

type mockSourceProvider struct {
	src sources.Source
}

func (m *mockSourceProvider) GetSource(name string) (sources.Source, bool) {
	if m.src == nil {
		return nil, false
	}
	return m.src, true
}

func newToolWithSource(sourceName, statement string, templateParams, stdParams parameters.Parameters) Tool {
	allParams := append(parameters.Parameters{}, templateParams...)
	allParams = append(allParams, stdParams...)
	return Tool{
		Config: Config{
			Name:               "test-tool",
			Type:               resourceType,
			Source:             sourceName,
			Description:        "test",
			Statement:          statement,
			Parameters:         stdParams,
			TemplateParameters: templateParams,
		},
		AllParams: allParams,
	}
}

func TestRequiresClientAuthorization(t *testing.T) {
	tests := []struct {
		name          string
		useClientAuth bool
		want          bool
	}{
		{name: "disabled", useClientAuth: false, want: false},
		{name: "enabled", useClientAuth: true, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &mockTrinoSource{useClientAuth: tt.useClientAuth}
			provider := &mockSourceProvider{src: src}
			tool := newToolWithSource("src", "SELECT 1", nil, nil)

			got, err := tool.RequiresClientAuthorization(provider)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("RequiresClientAuthorization() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetAuthTokenHeaderName(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		want       string
	}{
		{name: "default Authorization", headerName: "Authorization", want: "Authorization"},
		{name: "custom header", headerName: "X-Authenticated-User", want: "X-Authenticated-User"},
		{name: "another custom header", headerName: "X-Remote-User", want: "X-Remote-User"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := &mockTrinoSource{authHeaderName: tt.headerName}
			provider := &mockSourceProvider{src: src}
			tool := newToolWithSource("src", "SELECT 1", nil, nil)

			got, err := tool.GetAuthTokenHeaderName(provider)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("GetAuthTokenHeaderName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInvokeRoutesToRunSQL(t *testing.T) {
	expected := []map[string]any{{"id": 1}}
	src := &mockTrinoSource{
		useClientAuth: false,
		returnValue:   expected,
	}
	provider := &mockSourceProvider{src: src}
	tool := newToolWithSource("src",
		"SELECT * FROM {{.table}}",
		parameters.Parameters{parameters.NewStringParameter("table", "table name")},
		nil,
	)
	params := parameters.ParamValues{{Name: "table", Value: "my_catalog.my_schema.users"}}

	result, toolErr := tool.Invoke(context.Background(), provider, params, "")
	if toolErr != nil {
		t.Fatalf("unexpected error: %v", toolErr)
	}
	if !src.runSQLCalled {
		t.Fatal("expected RunSQL to be called")
	}
	if src.runSQLAsUserCalled {
		t.Fatal("RunSQLAsUser should not be called when client auth is disabled")
	}
	if src.lastStatement != "SELECT * FROM my_catalog.my_schema.users" {
		t.Errorf("statement = %q, want %q", src.lastStatement, "SELECT * FROM my_catalog.my_schema.users")
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestInvokeRoutesToRunSQLAsUser(t *testing.T) {
	expected := []map[string]any{{"id": 1}}
	src := &mockTrinoSource{
		useClientAuth: true,
		returnValue:   expected,
	}
	provider := &mockSourceProvider{src: src}
	tool := newToolWithSource("src",
		"SELECT * FROM {{.table}}",
		parameters.Parameters{parameters.NewStringParameter("table", "table name")},
		nil,
	)
	params := parameters.ParamValues{{Name: "table", Value: "my_catalog.my_schema.users"}}

	result, toolErr := tool.Invoke(context.Background(), provider, params, tools.AccessToken("alice"))
	if toolErr != nil {
		t.Fatalf("unexpected error: %v", toolErr)
	}
	if !src.runSQLAsUserCalled {
		t.Fatal("expected RunSQLAsUser to be called")
	}
	if src.runSQLCalled {
		t.Fatal("RunSQL should not be called when client auth is enabled")
	}
	if src.lastUser != "alice" {
		t.Errorf("user = %q, want %q", src.lastUser, "alice")
	}
	if src.lastStatement != "SELECT * FROM my_catalog.my_schema.users" {
		t.Errorf("statement = %q, want %q", src.lastStatement, "SELECT * FROM my_catalog.my_schema.users")
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestInvokeResolvesTemplateAndStandardParams(t *testing.T) {
	src := &mockTrinoSource{useClientAuth: false, returnValue: []map[string]any{}}
	provider := &mockSourceProvider{src: src}
	tool := newToolWithSource("src",
		"SELECT * FROM {{.table}} WHERE id = ?",
		parameters.Parameters{parameters.NewStringParameter("table", "table name")},
		parameters.Parameters{parameters.NewStringParameter("id", "row id")},
	)
	params := parameters.ParamValues{
		{Name: "table", Value: "catalog.schema.t"},
		{Name: "id", Value: "42"},
	}

	_, toolErr := tool.Invoke(context.Background(), provider, params, "")
	if toolErr != nil {
		t.Fatalf("unexpected error: %v", toolErr)
	}
	if src.lastStatement != "SELECT * FROM catalog.schema.t WHERE id = ?" {
		t.Errorf("statement = %q, want %q", src.lastStatement, "SELECT * FROM catalog.schema.t WHERE id = ?")
	}
	if len(src.lastParams) != 1 || src.lastParams[0] != "42" {
		t.Errorf("params = %v, want [42]", src.lastParams)
	}
}

func TestRequiresClientAuthorizationSourceNotFound(t *testing.T) {
	provider := &mockSourceProvider{src: nil}
	tool := newToolWithSource("missing-src", "SELECT 1", nil, nil)

	_, err := tool.RequiresClientAuthorization(provider)
	if err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestGetAuthTokenHeaderNameSourceNotFound(t *testing.T) {
	provider := &mockSourceProvider{src: nil}
	tool := newToolWithSource("missing-src", "SELECT 1", nil, nil)

	_, err := tool.GetAuthTokenHeaderName(provider)
	if err == nil {
		t.Fatal("expected error for missing source")
	}
}
