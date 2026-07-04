# Architecture

OpenSMART is split into a Python backend, a React frontend, and Bash operational hooks. The whole app lives under `OpenSMART/` at the repo root, alongside a `Containers/` tree for Docker-based deployment tooling and a root-level `opensmart.sh` entrypoint.

## Runtime Components

- Frontend: React + TypeScript + Vite, served by the Vite dev server during development.
- Backend: FastAPI application with SQLite persistence.
- Database: local SQLite file, defaulting to `OpenSMART/backend/opensmart.db`.
- Shell hooks: Bash scripts under `OpenSMART/backend/app/scripts/`, executed by Python with `subprocess.run([...], shell=False)`.

## Request Flow

1. Browser loads the React app from `http://localhost:5173`.
2. Vite proxies `/api` requests to `http://localhost:8000`.
3. FastAPI routes authenticate requests through session cookies.
4. Mutating routes require an `X-CSRF-Token` header matching the CSRF cookie/session value.
5. SQLite stores users, sessions, settings, module configuration, and failed-login counters.

## Backend Layout

- `OpenSMART/backend/app/main.py`: FastAPI app, middleware, startup initialization, router registration.
- `OpenSMART/backend/app/config.py`: environment-driven paths and app settings.
- `OpenSMART/backend/app/database.py`: SQLite schema, seed data, first-run admin bootstrap.
- `OpenSMART/backend/app/security.py`: password hashing, sessions, CSRF, login lockout, auth dependencies.
- `OpenSMART/backend/app/admin_tools.py`: admin password reset utility and admin action logging.
- `OpenSMART/backend/app/shell.py`: safe shell hook execution wrapper.
- `OpenSMART/backend/app/routes/`: API route modules.
- `OpenSMART/backend/app/scripts/`: Bash hooks used by backend routes.

## Frontend Layout

- `OpenSMART/frontend/src/App.tsx`: auth bootstrap and app-level state.
- `OpenSMART/frontend/src/api.ts`: fetch wrapper and API client functions.
- `OpenSMART/frontend/src/components/`: login, shell, and sidebar components.
- `OpenSMART/frontend/src/pages/`: OpenSMART modules, tools, account, status, audit, about, WebConsole Config, Tools Config, OpenSMART Config, wizard, and access pages.
- `OpenSMART/frontend/public/assets/`: local generated SVG assets for tool and summary cards.
- `OpenSMART/frontend/src/styles.css`: responsive dark theme and layout styles.

## Admin Bootstrap

On backend startup, `init_db()` creates the schema and default records. If no admin user exists, it creates username `admin` with a generated password and prints it once.

`OpenSMART/scripts/run_app.sh` watches backend startup output for the first-run marker and pauses so the operator can save the password before the frontend starts.

## Placeholder Integrations

The current tool integrations are placeholders. `GET /api/status` calls `OpenSMART/backend/app/scripts/module_status.sh`, which returns demo JSON. Tool entries use admin-configured internal URLs and load iframe content only after a tool is selected. Future production integrations should keep shell scripts thin and move complex logic into Python modules.

## Deployment

`opensmart.sh` at the repo root is the top-level entrypoint:

- `./opensmart.sh start --bind ADDRESS:PORT` parses the bind address/port and
  execs `OpenSMART/scripts/run_app.sh --host ADDRESS --port PORT`, which
  starts the backend (`uvicorn`) on that address/port and the frontend dev
  server on `5173`.
- `./opensmart.sh --install` is planned but **not yet implemented**. It will
  bootstrap Docker Engine (Debian/Ubuntu), build an `opensmart/web` image, and
  run the app as a container with `./opensmart.sh start --bind 0.0.0.0:8000`
  as its entrypoint.

`Containers/OpenSMART-Standalone/` is the existing reference Docker Compose
bundle for the network-sensor stack (Suricata, Zeek, Arkime, OpenSearch,
WireGuard, OpenVPN, nginx) — a standalone tool users can run and customize
separately, left untouched.

`Containers/build/` and `Containers/run/` now exist, copied from
`OpenSMART-Standalone`: `build/` holds Dockerfiles for the custom images
(`base`, `suricata`, `zeek`, `wireguard`, `openvpn` — official upstream images
like OpenSearch/Arkime/nginx have none), and `run/` holds one directory per
tool with its own `docker-compose.yaml` and a bind-mounted `volumes/data/`
directory (never a named Docker volume), including an empty `opensmart/`
placeholder for the future main-app container. Nothing wires `build/` and
`run/` together yet — that is `opensmart.sh --install`, still **not
implemented**.
