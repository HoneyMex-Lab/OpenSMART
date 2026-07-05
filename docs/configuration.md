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

## SQLite Runtime Settings

Runtime settings are stored in the `settings` table and are editable by admins from `Configuration > WebConsole Config`.

| Key | Default | Purpose |
|---|---|---|
| `platform_title` | `OpenSMART` | Sidebar and branding title. |
| `platform_version` | `v0.3 beta` | Version shown in the sidebar and About page. |
| `platform_build` | current git commit or `unknown` | Build identifier shown in app metadata. |
| `sensor_name` | host name or `OpenSMART Sensor` | Sensor name shown in telemetry and notifications. |
| `platform_language` | `en` | UI language. Supported values are `en` and `es-MX`. |
| `logo_url` | empty | Login and sidebar logo, managed through logo upload UI. |
| `favicon_url` | `/assets/branding/favicon.svg` | Browser favicon URL. |
| `footer_logo_primary` | empty | First sidebar footer logo, managed through logo upload UI. |
| `footer_logo_secondary` | empty | Second sidebar footer logo, managed through logo upload UI. |
| `developed_by` | `Developed by` | Sidebar footer text. |
| `failed_login_limit` | `5` | Failed login count before lockout. |
| `lockout_minutes` | `15` | Lockout duration after too many failed attempts. |
| `tool_base_path` | (none — set to a real path on the host) | Placeholder path for future local tool integrations. |
| `tool_url_opnsense` | empty | Internal iframe URL for OPNsense. |
| `tool_url_ntop` | empty | Internal iframe URL for NTOP. |
| `tool_url_arkime` | empty | Internal iframe URL for Arkime. |
| `tool_url_proxmox` | empty | Internal iframe URL for Proxmox. |
| `tool_url_wazuh` | empty | Internal iframe URL for Wazuh. |
| `tool_url_graylog` | empty | Internal iframe URL for Graylog. |
| `log_file_path` | `logs/opensmart.log` | Backend log file path. Relative paths resolve from the project root. |
| `worker_threads` | `8` | Backend worker thread limit for blocking work. |
| `dashboard_use_demo_for_disabled` | `false` | Shows demo dashboard values for disabled modules/tools when enabled. |
| `dashboard_feed_json` | `[]` | JSON feed for the home dashboard internal feed panel. |

Logo uploads are read by the browser and saved as data URLs in SQLite settings. Tool URLs are edited from `Configuration > Tools Config` and loaded only when a user clicks a tool sidebar item or card.

## Tools Config

`Settings > Tools` manages internal tools:

- enable/disable state
- internal iframe URL
- JSON configuration text

A tool status is derived automatically. Disabled tools show instructions instead of an iframe. Enabled tools without a URL show a warning message. Enabled tools with a URL load the iframe.

## OpenSMART Config

`Settings > OpenSMART Modules` manages OpenSMART modules:

- enable/disable state
- JSON configuration text

Disabled modules show enable/configuration instructions. Network IDS and Network Traffic Monitoring render live ingestion/analysis pages when enabled and configured. Other enabled modules currently show placeholder content.

Network IDS configuration includes the local Suricata `eve.json` path, initial ingestion size, summary refresh interval, analysis/detail page sizes, critical alert tracking, retention options, and optional GeoIP MMDB path for the attack map.

Network Traffic Monitoring configuration includes source selection, shared Suricata `eve.json` support, future Zeek JSON path configuration, protocol indexing toggles, excluded event types, and retention options.

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
