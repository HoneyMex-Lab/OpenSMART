# OpenSMART Prototype v0.3

OpenSMART is a prototype open source security operations framework. It combines a Python/FastAPI backend, SQLite local authentication, Bash operational hooks, and a responsive React/TypeScript frontend.

The current implementation is a working v0.3 prototype with local user management, admin configuration, basic security controls, operational status views, Network IDS ingestion, Network Traffic Monitoring, notification settings, and placeholder embedded tool frames for future integrations.

## Features

- Responsive React frontend with dark modern layout and collapsible sidebar.
- English and Spanish UI text selection through runtime platform settings.
- Local login backed by SQLite users and Argon2 password hashes.
- Generated first-run `admin` password with a pause so it can be saved before the frontend starts.
- Admin password reset flow from `scripts/run_app.sh --reset-admin-password`.
- HTTP-only session cookie plus CSRF token for mutating API requests.
- Configurable failed-login lockout by username and client IP.
- Admin-only Settings pages for Web Interface, OpenSMART Modules, Tools, Notifications, wizard placeholder, and user access.
- Sidebar links for each OpenSMART module and each internal tool with derived enabled/warning/disabled indicators.
- Home dashboard with module/tool readiness, host resource panels, configurable demo/feed values, and live Network IDS / Network Traffic panels when configured.
- Network IDS module with Suricata `eve.json` ingestion, summary tables, alert search/filtering, detail tables, query cancellation, critical alert tracking, acknowledgment actions, and GeoIP-backed attack map support.
- Network Traffic Monitoring module with shared `eve.json` ingestion, protocol/event summaries, details tables, filtering, query cancellation, and configurable protocol indexing. Zeek JSON configuration is present as a future ingestion option.
- Separate SQLite runtime databases for application data, Network IDS telemetry, and Network Traffic telemetry.
- Notifications configuration for outbound webhooks. IDS critical alerts and IDS system events can emit notifications in this release; other notification groups are placeholders.
- Status pages and API endpoints for host resources, resource history, data retention/info, and schema checks.
- Audit page showing relevant recent activity, with normal users limited to their own logons.
- Access page user actions for password changes and enable/disable state with confirmation prompts.
- Account page action to terminate all other active sessions.
- Logo uploads for main and footer branding stored in runtime settings.
- Tools Config page for internal iframe URLs.
- Bash backend hooks for operational integrations, currently represented by placeholder status scripts.
- Beta `opensmart-builder/` bundle for future deployment-builder work.

## Stack

- Backend: Python `>=3.11,<3.14` with Python `3.13` recommended, FastAPI, SQLite, Argon2.
- Backend dependency manager: `uv` by default.
- Backend scripts: Bash hooks under `backend/app/scripts/`.
- Frontend: React, TypeScript, Vite.
- Frontend dependency manager: npm.

## Project Structure

```text
.
├── backend/
│   ├── app/
│   │   ├── routes/
│   │   ├── scripts/
│   │   ├── admin_tools.py
│   │   ├── database.py
│   │   ├── main.py
│   │   ├── security.py
│   │   └── shell.py
│   ├── pyproject.toml
│   ├── requirements.txt
│   └── .env.example
├── docs/
├── frontend/
│   ├── src/
│   ├── package-lock.json
│   ├── package.json
│   └── vite.config.ts
├── logs/
├── opensmart-builder/
├── scripts/
└── README.md
```

## Requirements

- `uv`
- Python `>=3.11,<3.14`; Python `3.13` is recommended.
- Node.js and npm

Install `uv` if needed:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Install Node.js/npm from your operating system package manager or from `https://nodejs.org/`.

## Quick Start

```bash
./scripts/run_app.sh
```

The run script checks for `uv`, `node`, and `npm`, syncs backend dependencies with Python `3.13`, installs frontend dependencies when needed, prints a dependency summary, and starts both services if no errors occur.

If dependencies are already installed, it reports that they are OK and starts the app.

Open the frontend at:

```text
http://localhost:5173
```

The backend listens on:

```text
http://localhost:8000
```

## First-Run Admin Account

On first backend startup, the backend creates a local administrator if no admin user exists.

Default username:

```text
admin
```

The password is generated randomly and printed once. `run_app.sh` detects this first-run output and pauses before starting the frontend so you can save the password.

Change the password after first login from `Configuration > Account`.

## Reset Admin Password

To reset the local admin password:

```bash
./scripts/run_app.sh --reset-admin-password
```

The script asks you to type `RESET`, generates a new password, prints it once, logs action metadata to `logs/opensmart.log`, and exits. Run `./scripts/run_app.sh` again to start OpenSMART.

The generated password is not written to the log.

## Reset Telemetry Databases

To reset Network IDS and Network Traffic telemetry without touching users, settings, audit history, or other application data:

```bash
./scripts/reset_telemetry_db.sh
```

This recreates the IDS and Network Traffic SQLite databases used by the ingestion modules.

## Manual Setup

Backend with `uv`:

```bash
uv sync --project backend --python 3.13
./scripts/dev_backend.sh
```

Frontend in another terminal:

```bash
cd frontend
npm install
npm run dev
```

## Backend Compatibility Setup

`uv` is the recommended backend workflow. `backend/requirements.txt` is kept as a compatibility fallback:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements.txt
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

## Configuration

Runtime settings are stored in SQLite and editable from `Configuration > WebConsole Config` by admin users.

Current configurable settings include general web console values, language, uploaded logo/favicon data, dashboard demo/feed values, notification webhooks, internal tool URLs, tool enablement/configuration, and OpenSMART module enablement/configuration.

General settings:

- `platform_title`
- `platform_version`
- `platform_build`
- `sensor_name`
- `platform_language`
- `developed_by`
- `failed_login_limit`
- `lockout_minutes`
- `tool_base_path`
- `log_file_path`
- `worker_threads`
- dashboard demo/feed settings

Logo settings, managed from `WebConsole Config > Logo Uploads`:

- `logo_url`
- `favicon_url`
- `footer_logo_primary`
- `footer_logo_secondary`

Tool iframe URL settings and tool enablement/config JSON are managed from `Configuration > Tools Config`:

- `tool_url_opnsense`
- `tool_url_ntop`
- `tool_url_arkime`
- `tool_url_proxmox`
- `tool_url_wazuh`
- `tool_url_graylog`

OpenSMART module enablement and config JSON are managed from `Settings > OpenSMART Modules`.

Network IDS module configuration includes the local Suricata `eve.json` path, initial ingestion size, analysis page sizes, critical alert tracking, retention options, and optional GeoIP database path for the attack map.

Network Traffic Monitoring configuration includes the source selection, shared `eve.json` or future Zeek path, protocol indexing toggles, excluded event types, and retention options.

Notifications are managed from `Settings > Notifications`:

- IDS webhook URL and validation status.
- IDS critical alert notification toggle.
- IDS system event notification toggle.
- Network and platform notification groups reserved for future event emitters.

Status indicators are derived automatically:

- `disabled`: item is turned off.
- `warning`: tool is enabled but missing its internal URL.
- `enabled`: item is enabled and minimally configured.

Environment defaults are documented in `backend/.env.example` and `docs/configuration.md`.

Runtime SQLite files are separated by purpose:

- `backend/opensmart.db`: users, sessions, settings, audit events, catalog records, and resource snapshots.
- `backend/opensmart_network_ids.db`: Network IDS ingestion state, alerts, artifacts, FTS data, and tracking state.
- `backend/opensmart_network_traffic.db`: Network Traffic ingestion state and network events.
- `backend/opensmart_telemetry.db`: legacy compatibility telemetry database.

## Verification

Backend checks:

```bash
uv run --project backend python -m compileall backend/app
uv run --project backend python -c "import backend.app.admin_tools; import backend.app.main; print('backend imports ok')"
```

Shell checks:

```bash
bash -n scripts/run_app.sh scripts/dev_backend.sh scripts/dev_frontend.sh
```

Frontend checks, when Node.js/npm are installed:

```bash
cd frontend
npm install
npm run build
```

## Documentation

- `docs/architecture.md`: system structure and runtime flow.
- `docs/api.md`: backend API reference.
- `docs/configuration.md`: environment and runtime configuration.
- `docs/security.md`: security behavior and limitations.
- `docs/development.md`: local development workflow.

## Known Prototype Limitations

- Several OpenSMART module pages remain placeholder content outside Network IDS and Network Traffic Monitoring.
- Tool and summary icons are local generated SVG assets under `frontend/public/assets/`.
- Status data is placeholder JSON from `backend/app/scripts/module_status.sh`.
- There are no automated tests yet beyond syntax/import/build checks.
- Frontend dependency versions currently use broad ranges; keep `frontend/package-lock.json` tracked for reproducible frontend installs.
