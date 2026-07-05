# API Reference

The backend API is served from `http://localhost:8000`. During frontend development, Vite proxies `/api` to this backend.

## Authentication Model

- `POST /api/auth/login` creates a server-side session.
- The session token is stored in the `opensmart_session` HTTP-only cookie.
- The CSRF token is exposed through the `opensmart_csrf` cookie and returned by `GET /api/auth/me` as `user.csrfToken`.
- Mutating authenticated requests must send `X-CSRF-Token`.
- Admin-only endpoints require role `admin`.

## Public Endpoints

### `GET /api/health`

Returns basic backend health.

Response:

```json
{"ok": true}
```

### `GET /api/settings/public`

Returns public branding settings used by the login page.

Response:

```json
{
  "settings": {
    "platform_title": "OpenSMART",
    "platform_version": "v0.3 beta",
    "logo_url": "",
    "footer_logo_primary": "",
    "footer_logo_secondary": "",
    "developed_by": "Developed by"
  }
}
```

## Auth Endpoints

### `POST /api/auth/login`

Request:

```json
{"username":"admin","password":"generated-password"}
```

Response:

```json
{
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "fullName": "OpenSMART Administrator",
    "email": "",
    "mustChangePassword": true
  }
}
```

Failed logins are tracked by username and client IP. Lockout behavior is controlled by `failed_login_limit` and `lockout_minutes`.

`mustChangePassword` is `true` whenever the current password was *set for* the user rather than chosen by them (first-run bootstrap, an admin-created account, an admin's password reset, or the CLI `reset-admin-password`/`full-reset`). While it's true, every CSRF-protected endpoint except `/api/auth/me`, `/api/auth/logout`, and `/api/account/password` returns `423 Locked` — see [Account Endpoints](#account-endpoints) and `docs/security.md`.

### `GET /api/auth/me`

Requires a valid session cookie.

Response includes the CSRF token for frontend API calls:

```json
{
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "fullName": "OpenSMART Administrator",
    "email": "",
    "csrfToken": "token",
    "mustChangePassword": false
  }
}
```

### `POST /api/auth/logout`

Requires authentication and CSRF.

Destroys the current session and clears cookies.

## Account Endpoints

### `POST /api/account/password`

Requires authentication and CSRF. Exempt from the `mustChangePassword` lockout (see above) — this is the endpoint that clears it.

Request:

```json
{"currentPassword":"old-password","newPassword":"new-password"}
```

Response:

```json
{"ok": true}
```

`newPassword` is validated against the active `password_policy` setting (`strict` by default). A rejected password returns `400` with a detail message naming the policy and its requirements, e.g.:

```json
{"detail": "Password does not meet the 'strict' complexity policy (at least 12 characters and 4 of: lowercase, uppercase, digit, symbol)."}
```

### `PUT /api/account/profile`

Requires authentication and CSRF.

Updates the current user's editable profile fields only.

Request:

```json
{"fullName":"Operator Name","email":"operator@example.local"}
```

Response:

```json
{
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "fullName": "Operator Name",
    "email": "operator@example.local"
  }
}
```

### `GET /api/account/sessions`

Requires authentication.

Returns active sessions for the current user and the last 3 successful logons with date and IP address.

### `DELETE /api/account/sessions/others`

Requires authentication and CSRF.

Terminates all sessions for the current user except the current session and returns the refreshed session/logon list.

## Settings Endpoints

### `GET /api/settings`

Requires authentication.

Returns all runtime settings.

### `PUT /api/settings`

Requires admin and CSRF.

Updates allowlisted settings only.

Request:

```json
{
  "settings": {
    "platform_title": "OpenSMART",
    "failed_login_limit": "5",
    "lockout_minutes": "15",
    "password_policy": "strict",
    "wizard_completed": "true"
  }
}
```

`password_policy` is one of `strict` (default) / `moderate` / `low` / `disabled`. `wizard_completed` is managed by the app (defaults to `"true"` for existing installs, `"false"` only on a genuinely fresh install) but is a normal settable key like any other.

Tool iframe URLs are also allowlisted settings:

```json
{
  "settings": {
    "tool_url_opnsense": "https://opnsense.example.local",
    "tool_url_wazuh": "https://wazuh.example.local"
  }
}
```

## Module Endpoints

### `GET /api/modules`

Legacy compatibility endpoint. Requires authentication.

Returns module configuration records.

### `PUT /api/modules`

Requires admin and CSRF.

Request:

```json
[
  {"id":1,"enabled":true,"config":"{}"}
]
```

## Status Endpoint

### `GET /api/status`

Requires authentication.

Runs `opensmart/backend/app/scripts/module_status.sh` and returns parsed JSON.

Response:

```json
{
  "modules": [
    {"name":"Arkime","enabled":true,"status":"demo-online","detail":"Placeholder traffic session index"}
  ]
}
```

### `GET /api/status/resources`

Requires authentication.

Returns current host CPU, memory, disk, and uptime values.

### `GET /api/status/resources/history`

Requires authentication.

Returns sampled resource history for the requested timeframe.

### `GET /api/status/schema-check`

Requires authentication.

Checks the main application SQLite schema for expected tables and reports missing or unexpected tables.

### `GET /api/status/data-info`

Requires authentication.

Returns Network IDS and Network Traffic retention settings, earliest event timestamps, and event totals.

## Network IDS Endpoints

Network IDS endpoints require authentication and use the configured local Suricata `eve.json` source.

- `GET /api/network-ids/config`: configuration and ingestion state.
- `GET /api/network-ids/status`: cheap ingestion-progress polling endpoint.
- `GET /api/network-ids/summary`: summary counters and analysis tables, optionally refreshing ingestion.
- `POST /api/network-ids/summary/cancel`: cancel a running summary query.
- `GET /api/network-ids/alerts`: alert rows with filtering, sorting, pagination, and full-text search.
- `POST /api/network-ids/alerts/cancel`: cancel a running alert query.
- `GET /api/network-ids/details`: detail tables for IDS analysis.
- `POST /api/network-ids/details/cancel`: cancel a running details query.
- `GET /api/network-ids/attack-map`: GeoIP-backed attack map data.
- `POST /api/network-ids/tracking/ack`: acknowledge one alert.
- `POST /api/network-ids/tracking/ack-critical`: acknowledge critical alerts matching filters.

## Network Traffic Endpoints

Network Traffic endpoints require authentication and use the configured module source.

- `GET /api/network-traffic/config`: configuration and ingestion state.
- `GET /api/network-traffic/summary`: event/protocol summary tables, optionally refreshing ingestion.
- `POST /api/network-traffic/summary/cancel`: cancel a running summary query.
- `GET /api/network-traffic/details`: detail rows for selected traffic tables.
- `POST /api/network-traffic/details/cancel`: cancel a running details query.

## User Endpoints

User mutation endpoints require admin and CSRF. `GET /api/users` requires admin but does not require CSRF.

### `GET /api/users`

Returns all users without password hashes.

### `POST /api/users`

Creates a user.

Request:

```json
{
  "username": "operator",
  "password": "a-policy-compliant-password",
  "role": "user",
  "fullName": "Operator",
  "email": "operator@example.local",
  "enabled": true
}
```

`password` is validated against the active `password_policy` (same 400 error shape as `/api/account/password`). New users are created with `mustChangePassword: true`.

### `PUT /api/users/{user_id}`

Updates role, profile data, enabled state, and optionally password.

An admin cannot disable their own account.

The Access page uses this endpoint for admin password changes and enable/disable actions after user confirmation.

Setting `password` here validates it against the active policy, sets `mustChangePassword: true` for that user, and invalidates all of their existing sessions (forcing re-login with the new password) — matching the CLI's `reset-admin-password` behavior.

### `DELETE /api/users/{user_id}`

Deletes a user.

An admin cannot delete their own account.

## Tool Endpoints

### `GET /api/tools`

Requires authentication. Returns internal tool records with enablement and JSON config.

### `PUT /api/tools`

Requires admin and CSRF. Updates internal tool enablement and JSON config.

## OpenSMART Module Endpoints

### `GET /api/opensmart-modules`

Requires authentication. Returns OpenSMART platform modules with enablement and JSON config.

### `PUT /api/opensmart-modules`

Requires admin and CSRF. Updates OpenSMART module enablement and JSON config.

## Provisioning Endpoints

Start/stop the sibling tool containers (Suricata, Zeek, Arkime, OpenSearch, WireGuard, OpenVPN) backing enabled modules/tools, via a restricted Docker socket proxy — see `docs/technical-overview.md` for the full flow and security model.

### `POST /api/provisioning/start`

Requires admin and CSRF.

Request:

```json
{"name": "suricata", "kind": "container"}
```

`kind` is `container` (a specific container by name), `module`, or `tool` (looks up the container(s) that OpenSMART module/tool needs).

Response:

```json
{
  "name": "suricata",
  "ok": true,
  "detail": "Container opensmart-suricata Creating \n Container opensmart-suricata Created \n Container opensmart-suricata Starting \n Container opensmart-suricata Started",
  "containers": [{"container": "suricata", "ok": true, "detail": "..."}]
}
```

If the module/tool has no container template yet (Wazuh-backed modules, Graylog), `ok` is `false` and `detail` says so explicitly rather than the call silently doing nothing.

### `POST /api/provisioning/stop`

Requires admin and CSRF. Only accepts `kind: "container"` — modules/tools may need more than one container, so stopping is done per-container.

Request:

```json
{"name": "suricata", "kind": "container"}
```

### `GET /api/provisioning/status/{container}`

Requires admin (read).

Response:

```json
{"container": "suricata", "running": true, "detail": ""}
```

All three endpoints validate `container`/`name` against a fixed allowlist of container directories that actually exist under `opensmart/containers/run/` — never an arbitrary path — and are audit-logged (`provisioning_start`/`provisioning_stop`).

## Audit Endpoint

### `GET /api/audit`

Requires authentication.

Normal users receive only their own logon events. Admin users receive the last 100 relevant logons and configuration/user activity events, including `provisioning_start`/`provisioning_stop`.

## Account Sessions Endpoint

### `GET /api/account/sessions`

Requires authentication.

Returns active sessions for the current user and the last 3 successful logons with date and IP address.
