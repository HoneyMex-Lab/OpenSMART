# Configuration

OpenSMART uses two configuration layers: environment variables for process-level defaults and SQLite settings for runtime platform values.

## Environment Variables

Example values are in `backend/.env.example`.

| Variable | Default | Description |
|---|---|---|
| `OPENSMART_DB_PATH` | `backend/opensmart.db` | SQLite database path. |
| `OPENSMART_FRONTEND_ORIGIN` | `http://localhost:5173` | Allowed CORS origin for the frontend. |
| `OPENSMART_SESSION_TTL_HOURS` | `12` | Session lifetime in hours. |
| `OPENSMART_VERSION` | `v0.2` | Platform version used for seeded settings. |

The app reads these values directly from the environment. `.env` files are ignored by git.

## SQLite Runtime Settings

Runtime settings are stored in the `settings` table and are editable by admins from `Configuration > WebConsole Config`.

| Key | Default | Purpose |
|---|---|---|
| `platform_title` | `OpenSMART` | Sidebar and branding title. |
| `platform_version` | `v0.2` | Version shown in the sidebar and About page. |
| `logo_url` | empty | Login and sidebar logo, managed through logo upload UI. |
| `footer_logo_primary` | empty | First sidebar footer logo, managed through logo upload UI. |
| `footer_logo_secondary` | empty | Second sidebar footer logo, managed through logo upload UI. |
| `developed_by` | `Developed by` | Sidebar footer text. |
| `failed_login_limit` | `5` | Failed login count before lockout. |
| `lockout_minutes` | `15` | Lockout duration after too many failed attempts. |
| `tool_base_path` | `/opt/opensmart/tools` | Placeholder path for future local tool integrations. |
| `tool_url_opnsense` | empty | Internal iframe URL for OPNsense. |
| `tool_url_ntop` | empty | Internal iframe URL for NTOP. |
| `tool_url_arkime` | empty | Internal iframe URL for Arkime. |
| `tool_url_proxmox` | empty | Internal iframe URL for Proxmox. |
| `tool_url_wazuh` | empty | Internal iframe URL for Wazuh. |
| `tool_url_graylog` | empty | Internal iframe URL for Graylog. |

Logo uploads are read by the browser and saved as data URLs in SQLite settings. Tool URLs are edited from `Configuration > Tools Config` and loaded only when a user clicks a tool sidebar item or card.

## Tools Config

`Configuration > Tools Config` manages internal tools:

- enable/disable state
- internal iframe URL
- JSON configuration text

A tool status is derived automatically. Disabled tools show instructions instead of an iframe. Enabled tools without a URL show a warning message. Enabled tools with a URL load the iframe.

## OpenSMART Config

`Configuration > OpenSMART Config` manages OpenSMART modules:

- enable/disable state
- JSON configuration text

Disabled modules show enable/configuration instructions. Enabled modules currently show placeholder content.

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

- `backend/*.db`
- `backend/*.db-*`
- `backend/.env`
- `logs/*.log`
- virtual environments and frontend build artifacts

`logs/.gitkeep` is tracked so the log directory exists without committing runtime logs.
