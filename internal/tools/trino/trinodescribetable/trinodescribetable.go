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
	"fmt"
	"net/http"
	"strings"

	yaml "github.com/goccy/go-yaml"
	"github.com/googleapis/mcp-toolbox/internal/embeddingmodels"
	"github.com/googleapis/mcp-toolbox/internal/sources"
	"github.com/googleapis/mcp-toolbox/internal/tools"
	"github.com/googleapis/mcp-toolbox/internal/util"
	"github.com/googleapis/mcp-toolbox/internal/util/parameters"
)

const resourceType string = "trino-describe-table"

// tableParamName is the template parameter this tool reads the table name
// from. Initialize refuses to build a tool that does not declare it.
const tableParamName = "table"

// describeStatement returns one row per column, with Trino's native
// Column/Type/Extra/Comment result columns.
const describeStatement = "DESCRIBE {{." + tableParamName + "}}"

// commentStatement reads the table's own comment. The catalog filter is
// required: the same schema.table pair exists in more than one catalog on
// clusters that expose both an Iceberg and a Hive view of the warehouse, and
// without it the lookup returns several rows.
const commentStatement = "SELECT comment FROM system.metadata.table_comments " +
	"WHERE catalog_name = ? AND schema_name = ? AND table_name = ?"

// lookupFailed is the fixed marker returned in description_error. It is
// deliberately not the underlying error: Trino and policy-engine messages are
// not for LLM clients. The real error goes to the debug log.
const lookupFailed = "lookup_failed"

func init() {
	if !tools.Register(resourceType, newConfig) {
		panic(fmt.Sprintf("tool type %q already registered", resourceType))
	}
}

func newConfig(ctx context.Context, name string, decoder *yaml.Decoder) (tools.ToolConfig, error) {
	actual := Config{Name: name}
	if err := decoder.DecodeContext(ctx, &actual); err != nil {
		return nil, err
	}
	return actual, nil
}

type compatibleSource interface {
	RunSQL(context.Context, string, []any) (any, error)
	RunSQLAsUser(context.Context, string, []any, string) (any, error)
	UseClientAuthorization() bool
	GetAuthTokenHeaderName() string
	GetCatalog() string
	GetSchema() string
}

// Config is the YAML shape of a trino-describe-table tool. Unlike trino-sql
// there is no Statement field: this tool owns both statements it runs.
type Config struct {
	Name               string                 `yaml:"name" validate:"required"`
	Type               string                 `yaml:"type" validate:"required"`
	Source             string                 `yaml:"source" validate:"required"`
	Description        string                 `yaml:"description" validate:"required"`
	AuthRequired       []string               `yaml:"authRequired"`
	Parameters         parameters.Parameters  `yaml:"parameters"`
	TemplateParameters parameters.Parameters  `yaml:"templateParameters"`
	Annotations        *tools.ToolAnnotations `yaml:"annotations,omitempty"`

	ScopesRequired []string `yaml:"scopesRequired"`
}

// validate interface
var _ tools.ToolConfig = Config{}

func (cfg Config) ToolConfigType() string {
	return resourceType
}

func (cfg Config) Initialize(srcs map[string]sources.Source) (tools.Tool, error) {
	allParameters, paramManifest, err := parameters.ProcessParameters(cfg.TemplateParameters, cfg.Parameters)
	if err != nil {
		return nil, fmt.Errorf("unable to process parameters: %w", err)
	}

	// Fail at config load rather than returning an empty description forever.
	if !hasParam(cfg.TemplateParameters, tableParamName) {
		return nil, fmt.Errorf("tool %q of type %q requires a template parameter named %q", cfg.Name, resourceType, tableParamName)
	}

	t := Tool{
		Config:    cfg,
		AllParams: allParameters,
		manifest:  tools.Manifest{Description: cfg.Description, Parameters: paramManifest, AuthRequired: cfg.AuthRequired},
	}
	return t, nil
}

func hasParam(params parameters.Parameters, name string) bool {
	for _, p := range params {
		if p.GetName() == name {
			return true
		}
	}
	return false
}

// validate interface
var _ tools.Tool = Tool{}

type Tool struct {
	Config
	AllParams parameters.Parameters `yaml:"allParams"`
	manifest  tools.Manifest
}

func (t Tool) Invoke(ctx context.Context, resourceMgr tools.SourceProvider, params parameters.ParamValues, accessToken tools.AccessToken) (any, util.ToolboxError) {
	source, err := tools.GetCompatibleSource[compatibleSource](resourceMgr, t.Source, t.Name, t.Type)
	if err != nil {
		return nil, util.NewClientServerError("source not compatible with this tool", http.StatusInternalServerError, err)
	}

	paramsMap := params.AsMap()
	describeSQL, err := parameters.ResolveTemplateParams(t.TemplateParameters, describeStatement, paramsMap)
	if err != nil {
		return nil, util.NewAgentError("unable to extract template params", err)
	}

	// Columns first. This is also the authorization gate: a caller who cannot
	// read the table gets an error here and we never reach the comment lookup,
	// so the fallback below can never describe a table the caller cannot see.
	columns, err := t.run(ctx, source, describeSQL, nil, accessToken)
	if err != nil {
		return nil, util.ProcessGeneralError(err)
	}
	if columns == nil {
		columns = []any{}
	}

	out := map[string]any{
		"description": "",
		"columns":     columns,
	}

	rawTable, _ := paramsMap[tableParamName].(string)
	catalog, schema, table, ok := splitTableName(rawTable, source.GetCatalog(), source.GetSchema())
	if !ok {
		out["description_error"] = lookupFailed
		t.debug(ctx, "trino-describe-table: could not split table name", "table", rawTable)
		return out, nil
	}

	description, lookupErr := t.lookupDescription(ctx, source, []any{catalog, schema, table}, accessToken)
	if lookupErr != nil {
		// Never fail the call because the description could not be read: the
		// columns are still useful and describe_table did not error before.
		out["description_error"] = lookupFailed
		t.debug(ctx, "trino-describe-table: description lookup failed", "table", rawTable, "error", lookupErr)
		return out, nil
	}
	out["description"] = description
	return out, nil
}

// lookupDescription reads the table comment, preferring to send the caller's
// extra credential. Some deployments deny the system catalog to requests
// carrying one, so a failure is retried once with the credential blanked.
// The retry is not a privilege escalation: user impersonation is untouched,
// and DESCRIBE has already proven the caller can read this table.
func (t Tool) lookupDescription(ctx context.Context, source compatibleSource, args []any, accessToken tools.AccessToken) (string, error) {
	res, err := t.run(ctx, source, commentStatement, args, accessToken)
	if err != nil {
		t.debug(ctx, "trino-describe-table: retrying description lookup without extra credential", "error", err)
		res, err = t.run(util.WithExtraCredential(ctx, ""), source, commentStatement, args, accessToken)
		if err != nil {
			return "", err
		}
	}
	return firstComment(res), nil
}

func (t Tool) run(ctx context.Context, source compatibleSource, statement string, args []any, accessToken tools.AccessToken) (any, error) {
	if source.UseClientAuthorization() {
		return source.RunSQLAsUser(ctx, statement, args, string(accessToken))
	}
	return source.RunSQL(ctx, statement, args)
}

// debug logs without ever failing the call; a missing logger is not a reason
// to turn a working describe_table into an error.
func (t Tool) debug(ctx context.Context, msg string, args ...any) {
	logger, err := util.LoggerFromContext(ctx)
	if err != nil {
		return
	}
	logger.DebugContext(ctx, msg, args...)
}

// splitTableName resolves an optionally-qualified table name against the
// source's configured catalog and schema. The tool's allowedValues regex
// guarantees one to three dot-separated identifiers.
func splitTableName(raw, defaultCatalog, defaultSchema string) (catalog, schema, table string, ok bool) {
	parts := strings.Split(strings.TrimSpace(raw), ".")
	switch len(parts) {
	case 3:
		catalog, schema, table = parts[0], parts[1], parts[2]
	case 2:
		catalog, schema, table = defaultCatalog, parts[0], parts[1]
	case 1:
		catalog, schema, table = defaultCatalog, defaultSchema, parts[0]
	default:
		return "", "", "", false
	}
	if catalog == "" || schema == "" || table == "" {
		return "", "", "", false
	}
	return catalog, schema, table, true
}

// firstComment reads the comment out of the lookup result. A table with no
// comment returns no rows, which is not an error.
func firstComment(res any) string {
	rows, ok := res.([]any)
	if !ok || len(rows) == 0 {
		return ""
	}
	row, ok := rows[0].(map[string]any)
	if !ok {
		return ""
	}
	comment, ok := row["comment"].(string)
	if !ok {
		return ""
	}
	return comment
}

func (t Tool) EmbedParams(ctx context.Context, paramValues parameters.ParamValues, embeddingModelsMap map[string]embeddingmodels.EmbeddingModel) (parameters.ParamValues, error) {
	return parameters.EmbedParams(ctx, t.AllParams, paramValues, embeddingModelsMap, nil)
}

func (t Tool) Manifest() tools.Manifest {
	return t.manifest
}

func (t Tool) Authorized(verifiedAuthServices []string) bool {
	return tools.IsAuthorized(t.AuthRequired, verifiedAuthServices)
}

func (t Tool) RequiresClientAuthorization(resourceMgr tools.SourceProvider) (bool, error) {
	source, err := tools.GetCompatibleSource[compatibleSource](resourceMgr, t.Source, t.Name, t.Type)
	if err != nil {
		return false, err
	}
	return source.UseClientAuthorization(), nil
}

func (t Tool) GetName() string {
	return t.Name
}

func (t Tool) GetDescription() string {
	return t.Description
}

func (t Tool) GetAuthRequired() []string {
	return t.AuthRequired
}

// GetAnnotations reports this tool as read-only: it runs a DESCRIBE and a
// SELECT against a metadata table and changes nothing.
func (t Tool) GetAnnotations() *tools.ToolAnnotations {
	return tools.GetAnnotationsOrDefault(t.Annotations, tools.NewReadOnlyAnnotations)
}

func (t Tool) ToConfig() tools.ToolConfig {
	return t.Config
}

func (t Tool) GetAuthTokenHeaderName(resourceMgr tools.SourceProvider) (string, error) {
	source, err := tools.GetCompatibleSource[compatibleSource](resourceMgr, t.Source, t.Name, t.Type)
	if err != nil {
		return "", err
	}
	return source.GetAuthTokenHeaderName(), nil
}

func (t Tool) GetParameters() parameters.Parameters {
	return t.AllParams
}

func (t Tool) GetScopesRequired() []string {
	return t.ScopesRequired
}
