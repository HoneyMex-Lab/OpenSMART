# Configuration

OpenSMART uses two configuration layers: environment variables for process-level defaults and SQLite settings for runtime platform values.

## Environment Variables

Example values are in `opensmart/backend/.env.example`.

| Variable | Default | Description |
|---|---|---|
| `OPENSMART_DB_PATH` | `opensmart/backend/opensmart.db` | Main SQLite database path for users, sessions, settings, audit events, catalogs, and resource snapshots. |
| `OPENSMART_TELEMETRY_DB_PATH` | `opensmart/backend/opensmart_telemetry.db` | Legacy compatibility telemetry SQLite database path. |
| `OPENSMART_NETWORK_IDS_DB_PATH` | `opensmart/backend/opensmart_network_ids.db` | Network IDS telemetry SQLite database path. |
| `OPENSMART_NETWORK_TRAFFIC_DB_PATH` | `opensmart/backend/opensmart_network_traffic.db` | Network Traffic telemetry SQLite database path. |
| `OPENSMART_FRONTEND_ORIGIN` | `http://localhost:5173` | Allowed CORS origin for the frontend. |
| `OPENSMART_SESSION_TTL_HOURS` | `12` | Session lifetime in hours. |
| `OPENSMART_VERSION` | `v0.3 beta` | Platform version used for seeded settings. |

The app reads these values directly from the environment. `.env` files are ignored by git.

### Front-door proxy (`opensmart/containers/run/nginx/.env`)

The tools front-door proxy (see `docs/architecture.md` → "Tools Front-Door Proxy") reads two optional variables from a `.env` next to its compose file. They only affect the best-effort Proxmox/OPNsense aliases; Arkime/Wazuh use fixed internal upstreams.

| Variable | Default | Description |
|---|---|---|
| `PROXMOX_UPSTREAM` | `https://proxmox.invalid` | External Proxmox address the `/proxmox/` alias proxies to, e.g. `https://10.0.0.10:8006`. Unset → that alias returns 502. |
| `OPNSENSE_UPSTREAM` | `https://opnsense.invalid` | External OPNsense address for the `/opnsense/` alias. Unset → 502. |
| `OPENSMART_PROXY_BIND` | `0.0.0.0` | Host address the proxy's `:8080` port binds to. |

Host-specific tuning (`.env` files next to the relevant compose, all optional): `OPENSEARCH_JAVA_OPTS`, `WAZUH_INDEXER_JAVA_OPTS`, `WAZUH_MEMLOCK_LIMIT`, `WAZUH_MANAGER_NOFILE_LIMIT`, `WAZUH_INDEXER_NOFILE_LIMIT`, `ARKIME_ADMIN_PASSWORD`.

## SQLite Runtime Settings

Runtime settings are stored in the `settings` table and are editable by admins from `Configuration > WebConsole Config`.

| Key | Default | Purpose |
|---|---|---|
| `platform_title` | `OpenSMART` | Sidebar and branding title. |
| `platform_version` | `v0.3 beta` | Version shown in the sidebar and About page. Read-only — set from `OPENSMART_VERSION`, not editable from Settings. |
| `platform_build` | current git commit or `unknown` | Build identifier shown in app metadata. |
| `sensor_name` | host name or `OpenSMART Sensor` | Sensor name shown in telemetry and notifications. |
| `platform_language` | `en` | UI language. Supported values are `en` and `es-MX`. |
| `logo_url` | empty | Login and sidebar logo, managed through logo upload UI. |
| `favicon_url` | `/assets/branding/favicon.svg` | Browser favicon URL. |
| `footer_logo_primary` | empty | First sidebar footer logo, managed through logo upload UI. |
| `footer_logo_secondary` | empty | Second sidebar footer logo, managed through logo upload UI. |
| `developed_by` | `Developed by` | Sidebar footer text. Read-only — not editable from Settings. |
| `failed_login_limit` | `5` | Failed login count before lockout. |
| `lockout_minutes` | `15` | Lockout duration after too many failed attempts. |
| `password_policy` | `strict` | Password complexity profile: `strict` / `moderate` / `low` / `disabled`. See `docs/security.md`. |
| `wizard_completed` | `true` (`false` only on a genuinely fresh install) | Whether the first-run Wizard has been completed. Gates the Wizard redirect in `App.tsx`. |
| `theme` | `dark` | UI theme: `dark` / `classic` (light) / `matrix`. Exposed pre-login so the login page renders themed. |
| `monitor_interfaces` | empty | Comma-separated host NICs to capture on, chosen in the Wizard's Network step. Injected into Suricata as `CAPTURE_IFACES` on start (falls back to `eth0` when unset). |
| `tool_base_path` | `/opt/opensmart/tools` | Unused placeholder — not read by any backend code, not editable from Settings. |
| `tool_url_opnsense` | empty | Internal iframe URL for OPNsense. |
| `tool_url_ntop` | empty | Internal iframe URL for NTOP. |
| `tool_url_arkime` | empty | Internal iframe URL for Arkime. |
| `tool_url_proxmox` | empty | Internal iframe URL for Proxmox. |
| `tool_url_wazuh` | empty | Internal iframe URL for Wazuh. |
| `tool_url_graylog` | empty | Internal iframe URL for Graylog. |
| `log_file_path` | `logs/opensmart.log` | Backend log file path. Relative paths resolve from the project root. |
| `worker_threads` | `8` | Backend worker thread limit for blocking work. |

Logo uploads are read by the browser and saved as data URLs in SQLite settings. Tool URLs are edited from `Configuration > Tools Config` and loaded only when a user clicks a tool sidebar item or card.

## Tools Config

`Settings > Tools` manages internal tools:

- enable/disable state
- access mode + URL (see below)
- JSON configuration text

**Access mode** — tools the front-door proxy routes (Arkime, Wazuh, Proxmox, OPNsense) offer two modes:

- **Alias** — the URL is a same-origin path (`/arkime/`, `/wazuh/`, ...) served by the front-door proxy. The tool embeds in the Tools iframe (the proxy strips framing headers). Requires reaching OpenSMART through the proxy port (default `:8080`) so the relative path resolves. This is the Wizard default for locally-provisioned tools.
- **Direct URL** — an absolute `http://host:port`. Tools that block framing then open in a new tab instead of embedding.

A tool status is derived automatically. Disabled tools show instructions instead of an iframe. Enabled tools without a URL show a warning. Enabled tools with an alias URL embed; with a direct URL they embed if allowed or offer an "Open in new tab" launch card otherwise.

## OpenSMART Config

`Settings > OpenSMART Modules` manages OpenSMART modules:

- enable/disable state
- JSON configuration text

Disabled modules show enable/configuration instructions. Network IDS and Network Traffic Monitoring render live ingestion/analysis pages when enabled and configured. Other enabled modules currently show placeholder content.

Network IDS configuration includes an `eve.json` source toggle (`external`: a path you manage yourself, the default; or `native`: the bundled Suricata container, with a live Start/Stop control and an automatically-derived path — see `docs/technical-overview.md`), initial ingestion size, summary refresh interval, analysis/detail page sizes, critical alert tracking, retention options, and optional GeoIP MMDB path for the attack map.

Network Traffic Monitoring configuration includes source selection, shared Suricata `eve.json` support, future Zeek JSON path configuration, protocol indexing toggles, excluded event types, and retention options.

## First-Run Wizard

Shown automatically after the bootstrap admin's forced password change on a fresh install (`wizard_completed` setting is `false`); reachable manually afterward from `Settings > Wizard`. Four steps: Basics (app name + optional logo), Network (pick the host NICs to monitor — persisted as `monitor_interfaces`), Modules & Tools (recommended defaults pre-selected; enabling a Wazuh-backed module auto-enables the Wazuh tool with a visible notice; VPN type selector), and Provision (sequential runner with phases, a progress bar, per-service results and a final info/warning/error summary). See `docs/architecture.md` ("First-Run Wizard") for details.

## Notifications

`Settings > Notifications` manages outbound webhook URLs and event toggles.

Active emitters in this release:

- IDS critical alerts
- IDS system events

Network and platform notification groups are present as configuration placeholders for future event emitters.

## Internal Tools

Default internal tools are seeded on startup:

- Arkime
- OPNsense
- Proxmox
- Wazuh
- Graylog

The UI displays these with category prefixes such as `Firewall - OPNsense`, `Traffic - Arkime`, `Assets - Proxmox`, and `SIEM - Wazuh`.

Each tool stores:

- `name`
- `description`
- `enabled`
- `config`, currently a JSON string

Admins can edit tool enablement and config from `Configuration > Tools Config`.

## OpenSMART Modules

Default OpenSMART modules are seeded on startup:

- Threat Detection Alerts
- Network Traffic Monitoring
- Network IDS
- Endpoint
- Vulnerability Management
- Honeypot
- Access VPN
- LXC Manager

## Runtime Data

Ignored runtime files include:

- `opensmart/backend/*.db`
- `opensmart/backend/*.db-*`
- `opensmart/backend/.env`
- `logs/*.log`
- virtual environments and frontend build artifacts

`logs/.gitkeep` is tracked so the log directory exists without committing runtime logs.
