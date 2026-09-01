---
title: "Trino"
type: docs
description: "Details of the Trino prebuilt configuration."
---

## Trino

*   `--prebuilt` value: `trino`
*   **Environment Variables:**
    *   `TRINO_HOST`: The Trino coordinator hostname (default: `localhost`).
    *   `TRINO_PORT`: The Trino coordinator port (default: `8080`).
    *   `TRINO_USER`: The username for authentication. In impersonation setups, the service account principal.
    *   `TRINO_PASSWORD`: The password for basic authentication.
    *   `TRINO_CATALOG`: The default catalog to query (required).
    *   `TRINO_SCHEMA`: The default schema to query (default: `default`).
    *   `TRINO_SOURCE`: Source name for query attribution (`X-Trino-Source`).
    *   `TRINO_CLIENT_TAGS`: Static client tags (comma-separated) for `X-Trino-Client-Tags`.
    *   `TRINO_QUERY_TIMEOUT`: Query timeout duration (e.g. `30m`).
    *   `TRINO_SSL_ENABLED`: Enable SSL/TLS (default: `false`).
    *   `TRINO_DISABLE_SSL_VERIFICATION`: Skip SSL/TLS certificate verification (default: `false`).
    *   `TRINO_READ_ONLY_MODE`: Block DML/DDL, allowing only read-only statements (default: `true`).
    *   `TRINO_USE_CLIENT_AUTH`: HTTP header name to read the per-user identity from for impersonation (e.g. `X-Authenticated-User`).
*   **Tools:**
    *   `execute_sql`: Execute a read-only SQL query (SELECT, WITH, SHOW, DESCRIBE, EXPLAIN, VALUES).
    *   `list_catalogs`: List all catalogs available in the cluster.
    *   `list_schemas`: List all schemas in a given catalog.
    *   `list_tables`: List all tables in a given schema.
    *   `describe_table`: Describe a table: its own description plus its columns.
    *   `show_create_table`: Show the CREATE TABLE statement for a table.
    *   `show_stats`: Show table statistics.
    *   `sample_table`: Return a sample of rows from a table (with a LIMIT).
    *   `query_plan`: Show the execution plan for a SQL query without executing it.

By default the prebuilt config runs in read-only mode. Identifier parameters
(catalog, schema, table) are validated against an allowlist regex, and the
`query_plan` tool blocks semicolons and SQL comment syntax. See the
[Trino Source](../source.md) page for details on read-only enforcement, per-user
identity propagation, and client tag forwarding.
