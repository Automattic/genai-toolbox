---
title: "Looker"
type: docs
description: "Details of the Looker prebuilt configuration."
---

## Looker

*   `--prebuilt` value: `looker`
*   **Environment Variables:**
    *   `LOOKER_BASE_URL`: The URL of your Looker instance.
    *   `LOOKER_CLIENT_ID`: The client ID for the Looker API.
    *   `LOOKER_CLIENT_SECRET`: The client secret for the Looker API.
    *   `LOOKER_VERIFY_SSL`: Whether to verify SSL certificates.
    *   `LOOKER_USE_CLIENT_OAUTH`: Whether to use OAuth for authentication.
    *   `LOOKER_SHOW_HIDDEN_MODELS`: Whether to show hidden models.
    *   `LOOKER_SHOW_HIDDEN_EXPLORES`: Whether to show hidden explores.
    *   `LOOKER_SHOW_HIDDEN_FIELDS`: Whether to show hidden fields.
    *   `LOOKER_OAUTH_BASE_URL`: Public Looker URL for OAuth redirects. Enables the OAuth proxy when set.
    *   `LOOKER_OAUTH_CLIENT_ID`: OAuth client ID pre-registered in Looker. Required when `LOOKER_OAUTH_BASE_URL` is set.
    *   `LOOKER_OAUTH_CLIENT_SECRET`: OAuth client secret (empty for public PKCE clients).
    *   `LOOKER_OAUTH_TOKEN_ENDPOINT`: Override for the upstream token endpoint (defaults to `<base_url>/api/token`).
    *   `LOOKER_OAUTH_SCOPES`: Comma-separated OAuth scopes (defaults to `cors_api`).
*   **Permissions:**
    *   A Looker account with permissions to access the desired models,
        explores, and data is required.
*   **Tools:**
    *   `get_models`: Retrieves the list of LookML models.
    *   `get_explores`: Retrieves the list of explores in a model.
    *   `get_dimensions`: Retrieves the list of dimensions in an explore.
    *   `get_measures`: Retrieves the list of measures in an explore.
    *   `get_filters`: Retrieves the list of filters in an explore.
    *   `get_parameters`: Retrieves the list of parameters in an explore.
    *   `query`: Runs a query against the LookML model.
    *   `query_sql`: Generates the SQL for a query.
    *   `query_url`: Generates a URL for a query in Looker.
    *   `get_looks`: Searches for saved looks.
    *   `run_look`: Runs the query associated with a look.
    *   `make_look`: Creates a new look.
    *   `get_dashboards`: Searches for saved dashboards.
    *   `run_dashboard`: Runs the queries associated with a dashboard.
    *   `make_dashboard`: Creates a new dashboard.
    *   `add_dashboard_element`: Adds a tile to a dashboard.
    *   `add_dashboard_filter`: Adds a filter to a dashboard.
    *   `generate_embed_url`: Generate an embed url for content.
