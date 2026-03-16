---
title: "Trino"
type: docs
weight: 1
description: >
  Trino is a distributed SQL query engine for big data analytics.
---

## About

[Trino][trino-docs] is a distributed SQL query engine designed for fast analytic
queries against data of any size. It allows you to query data where it lives,
including Hive, Cassandra, relational databases or even proprietary data stores.

[trino-docs]: https://trino.io/docs/

## Available Tools

- [`trino-sql`](../tools/trino/trino-sql.md)  
  Execute parameterized SQL queries against Trino.

- [`trino-execute-sql`](../tools/trino/trino-execute-sql.md)  
  Execute arbitrary SQL queries against Trino.

## Requirements

### Trino Cluster

You need access to a running Trino cluster with appropriate user permissions for
the catalogs and schemas you want to query.

## Example

```yaml
kind: sources
name: my-trino-source
type: trino
host: trino.example.com
port: "8080"
user: ${TRINO_USER}  # Optional for anonymous access
password: ${TRINO_PASSWORD}  # Optional; required for service-account auth in impersonation setups
catalog: hive
schema: default
readOnlyMode: true
useClientAuth: X-Authenticated-User
```

{{< notice tip >}}
Use environment variable replacement with the format ${ENV_NAME}
instead of hardcoding your secrets into the configuration file.
{{< /notice >}}

## Reference

| **field**              | **type** | **required** | **description**                                                              |
| ---------------------- | :------: | :----------: | ---------------------------------------------------------------------------- |
| type                   |  string  |     true     | Must be "trino".                                                             |
| host                   |  string  |     true     | Trino coordinator hostname (e.g. "trino.example.com")                        |
| port                   |  string  |     true     | Trino coordinator port (e.g. "8080", "8443")                                 |
| user                   |  string  |    false     | Username for Trino authentication. In impersonation setups, this should be the service account principal (e.g. "mcp_service"). |
| password               |  string  |    false     | Password for basic authentication. Typically required with `user` in service-account impersonation setups. |
| catalog                |  string  |     true     | Default catalog to use for queries (e.g. "hive")                             |
| schema                 |  string  |     true     | Default schema to use for queries (e.g. "default")                           |
| queryTimeout           |  string  |    false     | Query timeout duration (e.g. "30m", "1h")                                    |
| accessToken            |  string  |    false     | JWT access token for authentication                                          |
| kerberosEnabled        | boolean  |    false     | Enable Kerberos authentication (default: false)                              |
| sslEnabled             | boolean  |    false     | Enable SSL/TLS (default: false)                                              |
| disableSslVerification | boolean  |    false     | Skip SSL/TLS certificate verification (default: false)                       |
| sslCertPath            |  string  |    false     | Path to a custom SSL/TLS certificate file                                    |
| sslCert                |  string  |    false     | Custom SSL/TLS certificate content                                           |
| readOnlyMode           | boolean  |    false     | Block DML/DDL statements, allowing only SELECT, WITH, SHOW, DESCRIBE, EXPLAIN, and VALUES (default: false) |
| useClientAuth          |  string  |    false     | HTTP header name to read per-user identity from (e.g. "X-Authenticated-User"). When set, Toolbox uses this value as the Trino session user via `X-Trino-User` per query. When empty, per-user mode is disabled and static source auth is used. |

## Security

### Read-only mode

When `readOnlyMode: true`, the Toolbox enforces a client-side allowlist before forwarding any SQL to Trino. The enforcement pipeline:

1. **Comment stripping** — SQL comments (`--` line comments and `/* */` block comments) are removed before analysis.
2. **Multi-statement rejection** — Semicolons outside string literals are rejected, blocking `SELECT 1; DROP TABLE t` style attacks.
3. **Prefix allowlist** — After normalization, only statements starting with `SELECT`, `WITH`, `SHOW`, `DESCRIBE`, `EXPLAIN`, or `VALUES` are allowed.

This is a best-effort client-side guard. For defense in depth, configure Trino-side role-based access control to restrict the user to read-only catalogs.

### Per-user identity propagation

When `useClientAuth` is set, each MCP/REST request must carry the user identity in the configured HTTP header. Toolbox authenticates to Trino with the configured source credentials (typically a service account) using a shared connection pool, then sets the effective query user per request via `X-Trino-User`.

In code, this is done with `sql.Named("X-Trino-User", "<user>")`, which the trino-go-client maps to a request header for that query. This enables Trino impersonation without creating per-user DB pools.

For this to work in production, Trino must be configured to allow impersonation from the authenticated service principal to the target users.

The trusted-header model assumes the header is set by an upstream authenticating proxy (e.g., nginx with LDAP/OAuth). Direct client access without a proxy would allow header spoofing.

### Prebuilt tool template validation

The prebuilt Trino config uses `allowedValues` regex on identifier parameters (catalog, schema, table) to restrict input to valid Trino identifiers (`[a-zA-Z_][a-zA-Z0-9_]*` optionally dot-separated). The `columns` parameter uses an allowlist regex restricting input to `*` or comma-separated identifier names (no expressions or subqueries). The `query` parameter (EXPLAIN tool) uses `excludedValues` to block semicolons and SQL comment syntax.
