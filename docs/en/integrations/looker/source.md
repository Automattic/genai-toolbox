---
title: "Looker Source"
linkTitle: "Source"
type: docs
weight: 1
description: >
  Looker is a business intelligence tool that also provides a semantic layer.
no_list: true
---

## About

[Looker][looker-docs] is a web based business intelligence and data management
tool that provides a semantic layer to facilitate querying. It can be deployed
in the cloud, on GCP, or on premises.

[looker-docs]: https://cloud.google.com/looker/docs



## Available Tools

{{< list-tools >}}

## Requirements

### Looker User

This source only uses API authentication. You will need to
[create an API user][looker-user] to login to Looker.

[looker-user]:
    https://cloud.google.com/looker/docs/api-auth#authentication_with_an_sdk

{{< notice note >}}
To use the Conversational Analytics API, you will need to have the following
Google Cloud Project API enabled and IAM permissions.
{{< /notice >}}

### API Enablement in GCP

Enable the following APIs in your Google Cloud Project:

```
gcloud services enable geminidataanalytics.googleapis.com --project=$PROJECT_ID
gcloud services enable cloudaicompanion.googleapis.com --project=$PROJECT_ID
```

### IAM Permissions in GCP

In addition to [setting the ADC for your server][set-adc], you need to ensure
the IAM identity has been given the following IAM roles (or corresponding
permissions):

- `roles/looker.instanceUser`
- `roles/cloudaicompanion.user`
- `roles/geminidataanalytics.dataAgentStatelessUser`

To initialize the application default credential run `gcloud auth login
--update-adc` in your environment before starting MCP Toolbox.

[set-adc]: https://cloud.google.com/docs/authentication/provide-credentials-adc

## Example

Initialize a Looker source for standard and development tools:

```yaml
kind: source
name: my-looker-source
type: looker
base_url: ${LOOKER_BASE_URL}
client_id: ${LOOKER_CLIENT_ID:}
client_secret: ${LOOKER_CLIENT_SECRET:}
verify_ssl: ${LOOKER_VERIFY_SSL:true}
timeout: 600s
use_client_oauth: ${LOOKER_USE_CLIENT_OAUTH:false}
show_hidden_models: ${LOOKER_SHOW_HIDDEN_MODELS:true}
show_hidden_explores: ${LOOKER_SHOW_HIDDEN_EXPLORES:true}
show_hidden_fields: ${LOOKER_SHOW_HIDDEN_FIELDS:true}
```

Initialize a Looker source for conversational analytics:

```yaml
kind: source
name: my-looker-conversational-source
type: looker
base_url: ${LOOKER_BASE_URL}
client_id: ${LOOKER_CLIENT_ID:}
client_secret: ${LOOKER_CLIENT_SECRET:}
verify_ssl: ${LOOKER_VERIFY_SSL:true}
timeout: 600s
use_client_oauth: ${LOOKER_USE_CLIENT_OAUTH:false}
project: ${LOOKER_PROJECT:}
location: ${LOOKER_LOCATION:}
```

The Looker base url will look like "https://looker.example.com", don't include
a trailing "/". In some cases, especially if your Looker is deployed
on-premises, you may need to add the API port number like
"https://looker.example.com:19999".

Verify ssl should almost always be "true" (all lower case) unless you are using
a self-signed ssl certificate for the Looker server. Anything other than "true"
will be interpreted as false.

The client id and client secret are seemingly random character sequences
assigned by the looker server. If you are using Looker OAuth you don't need
these settings

The `project` and `location` fields are utilized **only** when using the
conversational analytics tool.

{{< notice tip >}}
Use environment variable replacement with the format ${ENV_NAME}
instead of hardcoding your secrets into the configuration file.
{{< /notice >}}


## Reference

| **field**            | **type** | **required** | **description**                                                                                                                                     |
|----------------------|:--------:|:------------:|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| type                 |  string  |     true     | Must be "looker".                                                                                                                                   |
| base_url             |  string  |     true     | The URL of your Looker server with no trailing /.                                                                                                   |
| client_id            |  string  |    false     | The client id assigned by Looker.                                                                                                                   |
| client_secret        |  string  |    false     | The client secret assigned by Looker.                                                                                                               |
| verify_ssl           |  string  |    false     | Whether to check the ssl certificate of the server.                                                                                                 |
| project              |  string  |    false     | The project id to use in Google Cloud.                                                                                                              |
| location             |  string  |    false     | The location to use in Google Cloud. (default: us)                                                                                                  |
| timeout              |  string  |    false     | Maximum time to wait for query execution (e.g. "30s", "2m"). By default, 120s is applied.                                                           |
| use_client_oauth     |  string  |    false     | If set to `'true'`, forwards the client's OAuth access token from the default `Authorization` header. If set to a custom header name (e.g., `X-Looker-Auth`), that header will be used instead — but custom header values are only for non-proxy client OAuth; the OAuth proxy (`oauth_base_url`) requires `'true'`. An empty string or `'false'` disables this feature. Defaults to `""` (disabled). |
| show_hidden_models   |  string  |    false     | Show or hide hidden models. (default: true)                                                                                                         |
| show_hidden_explores |  string  |    false     | Show or hide hidden explores. (default: true)                                                                                                       |
| show_hidden_fields   |  string  |    false     | Show or hide hidden fields. (default: true)                                                                                                         |
| oauth_base_url       |  string  |    false     | Public Looker URL used for OAuth redirects (e.g. `https://looker.example.com`). Enables the OAuth proxy when set; requires `oauth_client_id` and `use_client_oauth: 'true'`. See [OAuth proxy](#oauth-proxy). |
| oauth_client_id      |  string  |    false     | OAuth client ID pre-registered in Looker. Required when `oauth_base_url` is set.                                                                    |
| oauth_client_secret  |  string  |    false     | OAuth client secret. Leave empty for public (PKCE) clients.                                                                                          |
| oauth_token_endpoint |  string  |    false     | Override for the upstream token endpoint. Defaults to `<base_url>/api/token`.                                                                        |
| oauth_scopes         |  string  |    false     | Comma-separated OAuth scopes requested. Defaults to `cors_api`. The proxy enforces these on `/authorize` (a client-supplied `scope` cannot widen them). |

### OAuth proxy

When `oauth_base_url`/`oauth_client_id` are set (with `use_client_oauth: 'true'`), Toolbox
exposes OAuth discovery and proxy endpoints (RFC 8414, RFC 9728) and advertises itself as the
authorization server: `/.well-known/oauth-protected-resource`,
`/.well-known/oauth-authorization-server`, `/authorize`, `/token`, and `/register`. This lets MCP
clients that rely on automatic OAuth discovery and Dynamic Client Registration (e.g. Claude Code,
Cursor) authenticate against Looker, which does not itself publish authorization-server metadata or
support RFC 7591. Toolbox proxies `/authorize` and `/token` to Looker with the configured
`oauth_client_id` (and `oauth_client_secret`) injected server-side, then forwards the resulting
access token to the Looker API per request.

Set [`--public-url`](../../reference/cli.md) to the externally reachable URL clients use, since it
is advertised in the OAuth metadata. The OAuth proxy is HTTP-only (not available over stdio). It
requires `use_client_oauth: 'true'` (custom header values are only for non-proxy client OAuth), and
cannot be combined with `--mcp-prm-file` or MCP server-wide auth (an `authService` with
`mcpEnabled`) — Toolbox fails to start if either is also configured, since they would both own the
protected-resource metadata endpoint or impose a competing auth gate.

Incoming bearer tokens are validated against Looker (the `me` API call) before any MCP method runs,
with a short-lived cache to bound upstream calls. The OAuth routes and middleware are bound at
startup; changing the OAuth configuration requires a restart (a dynamic config reload logs a warning
and does not re-mount them).
