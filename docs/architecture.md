# Architecture

OpenSMART is split into a Python backend, a React frontend, and Bash operational hooks. The whole app lives under `opensmart/` at the repo root, alongside a `containers/` tree for Docker-based deployment tooling and a root-level `opensmart.sh` entrypoint.

This document is the human-readable architecture reference. `docs/MANIFEST.json` is the machine-readable companion — the same facts (stack, layout, entrypoints, API surface, configuration, security posture, deployment status) in a structured format meant for tooling and coding agents to parse directly rather than scrape from prose.

## Runtime Components

- Frontend: React + TypeScript + Vite, served by the Vite dev server during development.
- Backend: FastAPI application with SQLite persistence.
- Database: local SQLite file, defaulting to `opensmart/backend/opensmart.db`.
- Shell hooks: Bash scripts under `opensmart/backend/app/scripts/`, executed by Python with `subprocess.run([...], shell=False)`.

## Request Flow

1. Browser loads the React app from `http://localhost:5173`.
2. Vite proxies `/api` requests to `http://localhost:8000`.
3. FastAPI routes authenticate requests through session cookies.
4. Mutating routes require an `X-CSRF-Token` header matching the CSRF cookie/session value.
5. SQLite stores users, sessions, settings, module configuration, and failed-login counters.

## Backend Layout

- `opensmart/backend/app/main.py`: FastAPI app, middleware, startup initialization, router registration.
- `opensmart/backend/app/config.py`: environment-driven paths and app settings.
- `opensmart/backend/app/database.py`: SQLite schema, seed data, first-run admin bootstrap.
- `opensmart/backend/app/security.py`: password hashing, sessions, CSRF, login lockout, auth dependencies.
- `opensmart/backend/app/admin_tools.py`: admin password reset utility and admin action logging.
- `opensmart/backend/app/shell.py`: safe shell hook execution wrapper.
- `opensmart/backend/app/routes/`: API route modules.
- `opensmart/backend/app/scripts/`: Bash hooks used by backend routes.

## Frontend Layout

- `opensmart/frontend/src/App.tsx`: auth bootstrap and app-level state.
- `opensmart/frontend/src/api.ts`: fetch wrapper and API client functions.
- `opensmart/frontend/src/components/`: login, shell, and sidebar components.
- `opensmart/frontend/src/pages/`: OpenSMART modules, tools, account, status, audit, about, WebConsole Config, Tools Config, OpenSMART Config, wizard, and access pages.
- `opensmart/frontend/public/assets/`: local generated SVG assets for tool and summary cards.
- `opensmart/frontend/src/styles.css`: responsive dark theme and layout styles.

## Admin Bootstrap

On backend startup, `init_db()` creates the schema and default records. If no admin user exists, it creates username `admin` with a generated password and prints it once.

`opensmart/scripts/run_app.sh` watches backend startup output for the first-run marker and pauses so the operator can save the password before the frontend starts.

## Placeholder Integrations

The current tool integrations are placeholders. `GET /api/status` calls `opensmart/backend/app/scripts/module_status.sh`, which returns demo JSON. Tool entries use admin-configured internal URLs and load iframe content only after a tool is selected. Future production integrations should keep shell scripts thin and move complex logic into Python modules.

## Deployment

`opensmart.sh` at the repo root is the top-level entrypoint:

- `./opensmart.sh start --bind ADDRESS:PORT [--prod]` parses the bind
  address/port and execs `opensmart/scripts/run_app.sh --host ADDRESS --port
  PORT [--prod]`. Without `--prod`, this starts the backend (`uvicorn`) on
  that address/port and the frontend dev server on `5173`, same as always.
  With `--prod`, it builds the frontend once (`npm run build`) instead of
  starting the Vite dev server, skips the interactive first-run
  password-reveal prompt, and lets the backend serve the built frontend
  itself (see below) — this is the mode the container entrypoint uses.
- `./opensmart.sh --install` bootstraps Docker Engine on Debian/Ubuntu (apt
  only), creates the `opensmart` bridge network, builds the `opensmart/web`
  image from `containers/build/opensmart/Dockerfile`, chowns the bind-mounted
  app directory to uid 1000 (the container's non-root `opensmart` user; a
  root-owned checkout otherwise leaves the container unable to create
  `.venv`/`node_modules`/the SQLite DBs), and runs it via
  `containers/run/opensmart/docker-compose.yml` with
  `./opensmart.sh start --bind 0.0.0.0:8000 --prod` as its command. It must
  run as root. **Verified against a real Docker Engine** on a Debian 13 test
  host: a fresh install ends with a stable container serving `/api/health`
  and the built frontend, and the initial admin password extracted from
  `docker logs`. A cold install (no cached `.venv`/`node_modules`) can take a
  few minutes to build the frontend and sync backend dependencies inside the
  container before it's reachable.

**Single-port production serving:** `opensmart/backend/app/main.py` mounts
`opensmart/frontend/dist` as static files (via `fastapi.staticfiles.StaticFiles`,
mounted after all API routes) whenever `frontend/dist/index.html` exists. In
the normal dev workflow that file is never built, so this is inert; `--prod`
mode is what actually builds it.

**Known caveat:** if `opensmart/backend/.venv` or `opensmart/frontend/node_modules`
already exist from host-side development, delete them before the first
container run — they were built for the host's platform/libc, not the
container's, and their mere presence skips `run_app.sh`'s reinstall step
(the same class of problem hit for real during the Phase 1 directory move,
where a moved `.venv`'s shebangs pointed at a now-nonexistent path).

`containers/OpenSMART-Standalone/` is the existing reference Docker Compose
bundle for the network-sensor stack (Suricata, Zeek, Arkime, OpenSearch,
WireGuard, OpenVPN, nginx) — a standalone tool users can run and customize
separately, left untouched.

`containers/build/` and `containers/run/` hold the per-tool Dockerfiles and
compose files copied from `OpenSMART-Standalone` (`base`, `suricata`, `zeek`,
`wireguard`, `openvpn` — official upstream images like OpenSearch/Arkime/nginx
have none), plus `containers/build/opensmart/Dockerfile` and
`containers/run/opensmart/docker-compose.yml` for the main app container
(self-contained image, whole repo bind-mounted at `/opt/opensmart`, no
Linux-user password or sudo — `docker exec` doesn't need one and nothing in
`start --prod` requires root).
