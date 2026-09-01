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

package trinodescribetable

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/googleapis/mcp-toolbox/internal/sources"
	"github.com/googleapis/mcp-toolbox/internal/tools"
	"github.com/googleapis/mcp-toolbox/internal/util"
	"github.com/googleapis/mcp-toolbox/internal/util/parameters"
)

// recordedCall captures everything a test needs to assert about one query,
// including the extra credential carried on its context.
type recordedCall struct {
	statement string
	params    []any
	user      string
	asUser    bool
	cred      string
}

type mockResponse struct {
	val any
	err error
}

// mockTrinoSource answers queries from a fixed list of responses, one per
// call, so a test can make the first lookup fail and the retry succeed.
type mockTrinoSource struct {
	useClientAuth bool
	catalog       string
	schema        string
	responses     []mockResponse
	calls         []recordedCall
}

func (m *mockTrinoSource) SourceType() string             { return "trino" }
func (m *mockTrinoSource) ToConfig() sources.SourceConfig { return nil }
func (m *mockTrinoSource) UseClientAuthorization() bool   { return m.useClientAuth }
func (m *mockTrinoSource) GetAuthTokenHeaderName() string { return "X-Authenticated-User" }
func (m *mockTrinoSource) GetCatalog() string             { return m.catalog }
func (m *mockTrinoSource) GetSchema() string              { return m.schema }

func (m *mockTrinoSource) record(ctx context.Context, stmt string, params []any, user string, asUser bool) (any, error) {
	m.calls = append(m.calls, recordedCall{
		statement: stmt,
		params:    params,
		user:      user,
		asUser:    asUser,
		cred:      util.ExtraCredentialFromContext(ctx),
	})
	idx := len(m.calls) - 1
	if idx >= len(m.responses) {
		return []any{}, nil
	}
	return m.responses[idx].val, m.responses[idx].err
}

func (m *mockTrinoSource) RunSQL(ctx context.Context, stmt string, params []any) (any, error) {
	return m.record(ctx, stmt, params, "", false)
}

func (m *mockTrinoSource) RunSQLAsUser(ctx context.Context, stmt string, params []any, user string) (any, error) {
	return m.record(ctx, stmt, params, user, true)
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

func newTool(sourceName string) Tool {
	tp := parameters.Parameters{parameters.NewStringParameter(tableParamName, "table name")}
	return Tool{
		Config: Config{
			Name:               "describe_table",
			Type:               resourceType,
			Source:             sourceName,
			Description:        "test",
			TemplateParameters: tp,
		},
		AllParams: tp,
	}
}

func columnRows() []any {
	return []any{
		map[string]any{"Column": "ts", "Type": "bigint", "Extra": "", "Comment": "event time"},
		map[string]any{"Column": "userid", "Type": "varchar", "Extra": "", "Comment": ""},
	}
}

func commentRows(comment string) []any {
	return []any{map[string]any{"comment": comment}}
}

func invoke(t *testing.T, src *mockTrinoSource, table string, token tools.AccessToken) (map[string]any, util.ToolboxError) {
	t.Helper()
	tool := newTool("src")
	provider := &mockSourceProvider{src: src}
	params := parameters.ParamValues{{Name: tableParamName, Value: table}}
	res, toolErr := tool.Invoke(context.Background(), provider, params, token)
	if res == nil {
		return nil, toolErr
	}
	out, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T, want map[string]any", res)
	}
	return out, toolErr
}

// 1. Name splitting resolves against the source's configured defaults.
func TestSplitTableName(t *testing.T) {
	tests := []struct {
		name                             string
		raw                              string
		defCatalog, defSchema            string
		wantCatalog, wantSchema, wantTbl string
		wantOK                           bool
	}{
		{"bare table uses both defaults", "prod_events", "iceberg", "default", "iceberg", "default", "prod_events", true},
		{"schema qualified uses default catalog", "tracks.prod_events", "iceberg", "default", "iceberg", "tracks", "prod_events", true},
		{"fully qualified ignores defaults", "wyeast.tracks.prod_events", "iceberg", "default", "wyeast", "tracks", "prod_events", true},
		{"missing default catalog is not resolvable", "tracks.prod_events", "", "default", "", "", "", false},
		{"too many parts", "a.b.c.d", "iceberg", "default", "", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, s, tbl, ok := splitTableName(tc.raw, tc.defCatalog, tc.defSchema)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if c != tc.wantCatalog || s != tc.wantSchema || tbl != tc.wantTbl {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)", c, s, tbl, tc.wantCatalog, tc.wantSchema, tc.wantTbl)
			}
		})
	}
}

// 2. Happy path: columns and description are merged into the documented shape.
func TestInvokeMergesDescriptionAndColumns(t *testing.T) {
	src := &mockTrinoSource{
		catalog: "iceberg",
		schema:  "default",
		responses: []mockResponse{
			{val: columnRows()},
			{val: commentRows("Canonical Tracks events table")},
		},
	}
	out, toolErr := invoke(t, src, "tracks.prod_events", "")
	if toolErr != nil {
		t.Fatalf("unexpected error: %v", toolErr)
	}
	if got := out["description"]; got != "Canonical Tracks events table" {
		t.Errorf("description = %v, want the table comment", got)
	}
	if _, present := out["description_error"]; present {
		t.Error("description_error must be absent on the happy path")
	}
	if !reflect.DeepEqual(out["columns"], columnRows()) {
		t.Errorf("columns = %v, want the DESCRIBE rows unchanged", out["columns"])
	}
	if len(src.calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(src.calls))
	}
	if src.calls[0].statement != "DESCRIBE tracks.prod_events" {
		t.Errorf("first statement = %q", src.calls[0].statement)
	}
	if src.calls[1].statement != commentStatement {
		t.Errorf("second statement = %q, want the table_comments lookup", src.calls[1].statement)
	}
	wantArgs := []any{"iceberg", "tracks", "prod_events"}
	if !reflect.DeepEqual(src.calls[1].params, wantArgs) {
		t.Errorf("lookup args = %v, want %v (catalog filter is required)", src.calls[1].params, wantArgs)
	}
}

// 3. A table with no comment yields an empty description and no error marker.
func TestInvokeNoComment(t *testing.T) {
	src := &mockTrinoSource{
		catalog: "iceberg",
		schema:  "default",
		responses: []mockResponse{
			{val: columnRows()},
			{val: []any{}},
		},
	}
	out, toolErr := invoke(t, src, "tracks.prod_useraliases", "")
	if toolErr != nil {
		t.Fatalf("unexpected error: %v", toolErr)
	}
	if out["description"] != "" {
		t.Errorf("description = %v, want empty", out["description"])
	}
	if _, present := out["description_error"]; present {
		t.Error("an undocumented table is not a lookup failure")
	}
	if !reflect.DeepEqual(out["columns"], columnRows()) {
		t.Error("columns should still be returned in full")
	}
}

// 4. Both lookup attempts failing still returns the columns, plus the marker.
func TestInvokeLookupFailsBothAttempts(t *testing.T) {
	src := &mockTrinoSource{
		catalog: "iceberg",
		schema:  "default",
		responses: []mockResponse{
			{val: columnRows()},
			{err: errors.New("access denied to system catalog")},
			{err: errors.New("access denied to system catalog")},
		},
	}
	out, toolErr := invoke(t, src, "tracks.prod_events", "")
	if toolErr != nil {
		t.Fatalf("a failed description lookup must not fail the call: %v", toolErr)
	}
	if out["description"] != "" {
		t.Errorf("description = %v, want empty", out["description"])
	}
	if out["description_error"] != lookupFailed {
		t.Errorf("description_error = %v, want %q", out["description_error"], lookupFailed)
	}
	if !reflect.DeepEqual(out["columns"], columnRows()) {
		t.Error("columns should still be returned in full")
	}
	if len(src.calls) != 3 {
		t.Errorf("calls = %d, want 3 (describe, lookup, retry)", len(src.calls))
	}
}

// 5. DESCRIBE failing is the authorization gate: the lookup never runs.
func TestInvokeDescribeErrorSkipsLookup(t *testing.T) {
	src := &mockTrinoSource{
		catalog: "iceberg",
		schema:  "default",
		responses: []mockResponse{
			{err: errors.New("table not found")},
		},
	}
	out, toolErr := invoke(t, src, "tracks.secret_table", "")
	if toolErr == nil {
		t.Fatal("expected the DESCRIBE error to be returned")
	}
	if out != nil {
		t.Errorf("result = %v, want nil when DESCRIBE fails", out)
	}
	if len(src.calls) != 1 {
		t.Fatalf("calls = %d, want 1: no description may be looked up for a table the caller cannot read", len(src.calls))
	}
}

// 6. The retry drops the extra credential, and only the retry does.
func TestInvokeFallbackStripsCredentialOnRetry(t *testing.T) {
	src := &mockTrinoSource{
		useClientAuth: true,
		catalog:       "iceberg",
		schema:        "default",
		responses: []mockResponse{
			{val: columnRows()},
			{err: errors.New("access denied to system catalog")},
			{val: commentRows("Canonical Tracks events table")},
		},
	}
	tool := newTool("src")
	provider := &mockSourceProvider{src: src}
	ctx := util.WithExtraCredential(context.Background(), "ai-tool=ai-billing")
	params := parameters.ParamValues{{Name: tableParamName, Value: "tracks.prod_events"}}

	res, toolErr := tool.Invoke(ctx, provider, params, tools.AccessToken("alice"))
	if toolErr != nil {
		t.Fatalf("unexpected error: %v", toolErr)
	}
	out, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("result type = %T", res)
	}
	if out["description"] != "Canonical Tracks events table" {
		t.Errorf("description = %v, want the comment from the retry", out["description"])
	}
	if _, present := out["description_error"]; present {
		t.Error("a successful retry is not a failure")
	}
	if len(src.calls) != 3 {
		t.Fatalf("calls = %d, want 3", len(src.calls))
	}
	if src.calls[0].cred != "ai-tool=ai-billing" {
		t.Errorf("DESCRIBE credential = %q, want it carried through untouched", src.calls[0].cred)
	}
	if src.calls[1].cred != "ai-tool=ai-billing" {
		t.Errorf("first lookup credential = %q, want it sent before we ever drop it", src.calls[1].cred)
	}
	if src.calls[2].cred != "" {
		t.Errorf("retry credential = %q, want it blanked", src.calls[2].cred)
	}
	for i, c := range src.calls {
		if !c.asUser || c.user != "alice" {
			t.Errorf("call %d: asUser=%v user=%q, want impersonation preserved on every query", i, c.asUser, c.user)
		}
	}
}

// 7. We never strip the credential when we did not have to.
func TestInvokeNoFallbackWhenLookupSucceeds(t *testing.T) {
	src := &mockTrinoSource{
		useClientAuth: true,
		catalog:       "iceberg",
		schema:        "default",
		responses: []mockResponse{
			{val: columnRows()},
			{val: commentRows("documented")},
		},
	}
	tool := newTool("src")
	provider := &mockSourceProvider{src: src}
	ctx := util.WithExtraCredential(context.Background(), "ai-tool=ai-billing")
	params := parameters.ParamValues{{Name: tableParamName, Value: "tracks.prod_events"}}

	if _, toolErr := tool.Invoke(ctx, provider, params, tools.AccessToken("alice")); toolErr != nil {
		t.Fatalf("unexpected error: %v", toolErr)
	}
	if len(src.calls) != 2 {
		t.Fatalf("calls = %d, want 2: no retry when the first lookup works", len(src.calls))
	}
	for i, c := range src.calls {
		if c.cred != "ai-tool=ai-billing" {
			t.Errorf("call %d credential = %q, want it never dropped", i, c.cred)
		}
	}
}

// Initialize refuses a tool that cannot supply a table name, rather than
// silently returning an empty description forever.
func TestInitializeRequiresTableParameter(t *testing.T) {
	cfg := Config{
		Name:               "describe_table",
		Type:               resourceType,
		Source:             "src",
		Description:        "test",
		TemplateParameters: parameters.Parameters{parameters.NewStringParameter("schema", "schema name")},
	}
	if _, err := cfg.Initialize(map[string]sources.Source{}); err == nil {
		t.Fatal("expected an error when no 'table' template parameter is declared")
	}

	cfg.TemplateParameters = parameters.Parameters{parameters.NewStringParameter(tableParamName, "table name")}
	if _, err := cfg.Initialize(map[string]sources.Source{}); err != nil {
		t.Fatalf("unexpected error with a table parameter: %v", err)
	}
}

// The tool is read-only and must advertise itself as such.
func TestAnnotationsAreReadOnly(t *testing.T) {
	got := newTool("src").GetAnnotations()
	if got == nil || got.ReadOnlyHint == nil || !*got.ReadOnlyHint {
		t.Fatalf("annotations = %+v, want readOnlyHint true", got)
	}
}
