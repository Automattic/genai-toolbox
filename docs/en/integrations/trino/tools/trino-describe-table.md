---
title: "trino-describe-table"
type: docs
weight: 1
description: >
  A "trino-describe-table" tool returns a Trino table's own description
  along with its columns.
---

## About

A `trino-describe-table` tool describes one table: it returns the description
set on the table itself, plus one entry per column with that column's name,
type and comment.

It runs two queries. First `DESCRIBE <table>`, which returns the columns.
Then a lookup against `system.metadata.table_comments`, which returns the
comment stored on the table. Trino has no single statement that returns both.

The table name may be unqualified (`my_table`), schema-qualified
(`my_schema.my_table`) or fully qualified
(`my_catalog.my_schema.my_table`). Names that leave out the catalog or schema
are resolved against the ones the source is configured with. The catalog
always takes part in the lookup, because the same `schema.table` pair can
exist in more than one catalog on clusters that expose the same warehouse
through several connectors.

Reading the description never causes the tool to fail. If the lookup cannot
run, the columns are returned as usual with an empty `description` and a
`description_error` field explaining that the lookup did not complete. A table
that simply has no comment returns an empty `description` and no
`description_error`.

The tool requires a template parameter named `table`. A configuration without
one is rejected when the server starts, rather than returning an empty
description at runtime.

## Compatible Sources

{{< compatible-sources >}}

## Example

```yaml
kind: tool
name: describe_table
type: trino-describe-table
source: my-trino-instance
description: "Describe a table: returns the table's own description (the comment set on it, when there is one) together with one entry per column giving its name, type and comment."
templateParameters:
  - name: table
    type: string
    description: "The table name, optionally qualified with schema and catalog (e.g. 'my_table', 'my_schema.my_table', or 'my_catalog.my_schema.my_table')."
    required: true
    allowedValues: ["^[a-zA-Z_][a-zA-Z0-9_]*(\\.[a-zA-Z_][a-zA-Z0-9_]*){0,2}$"]
```

## Output Format

```json
{
  "description": "One row per validated event. Always filter on the partition column.",
  "columns": [
    {"Column": "ts", "Type": "bigint", "Extra": "", "Comment": "Event time in epoch milliseconds"},
    {"Column": "userid", "Type": "varchar", "Extra": "", "Comment": ""}
  ]
}
```

| **field**         | **type** | **description**                                                                                                              |
|-------------------|:--------:|------------------------------------------------------------------------------------------------------------------------------|
| description       |  string  | The comment stored on the table, returned exactly as the catalog holds it. Empty when the table has no comment.               |
| description_error |  string  | Present only when the description could not be read. The columns are still complete. Value is `lookup_failed`.                |
| columns           |  array   | The rows returned by `DESCRIBE`, unchanged, with Trino's own `Column`, `Type`, `Extra` and `Comment` keys.                    |

## Reference

| **field**          |                   **type**                   | **required** | **description**                                                                              |
|--------------------|:--------------------------------------------:|:------------:|-----------------------------------------------------------------------------------------------|
| type               |                    string                    |     true     | Must be "trino-describe-table".                                                              |
| source             |                    string                    |     true     | Name of the source to describe the table on.                                                 |
| description        |                    string                    |     true     | Description of the tool that is passed to the LLM.                                           |
| templateParameters | [templateParameters](../../../documentation/configuration/tools/_index.md#template-parameters) |     true     | Must include a parameter named `table`. Constrain it with `allowedValues` as shown above.    |
| parameters         |   [parameters](../../../documentation/configuration/tools/_index.md#specifying-parameters)    |    false     | Additional parameters. This tool builds its own statements and does not interpolate them.    |
| authRequired       |                array of string               |    false     | Auth services required to use this tool.                                                     |

## Advanced Usage

### Clusters that restrict the system catalog

The description lookup reads `system.metadata.table_comments`. Some
deployments deny the `system` catalog to requests that carry an
`X-Trino-Extra-Credential` header, which is how a gateway marks traffic that
came from an AI client. A description lookup sent with such a credential would
be refused on those clusters, and the tool would never return a description
for the clients that most need one.

The tool handles this by preferring to send the credential and only dropping
it when the cluster refuses. The lookup runs first with the credential
untouched. Only if that query returns an error is it retried once with the
credential blanked. Once a policy allows `system.metadata.table_comments`, the
first attempt succeeds and the retry stops happening on its own.

Two properties make the retry safe:

- **User identity is unchanged.** Impersonation is untouched, so the retry
  still runs as the end user and is still subject to that user's permissions.
  Only the marker identifying the calling tool is dropped.
- **Authorization is proven first.** The lookup runs only after `DESCRIBE` has
  already succeeded for the same table. A caller who cannot read the table
  gets an error from `DESCRIBE`, and no description is ever looked up.
