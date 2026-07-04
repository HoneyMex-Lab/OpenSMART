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

- `./opensmart.sh start --bind ADDRESS:PORT [--prod]` parses the bind
  address/port and execs `OpenSMART/scripts/run_app.sh --host ADDRESS --port
  PORT [--prod]`. Without `--prod`, this starts the backend (`uvicorn`) on
  that address/port and the frontend dev server on `5173`, same as always.
  With `--prod`, it builds the frontend once (`npm run build`) instead of
  starting the Vite dev server, skips the interactive first-run
  password-reveal prompt, and lets the backend serve the built frontend
  itself (see below) — this is the mode the container entrypoint uses.
- `./opensmart.sh --install` bootstraps Docker Engine on Debian/Ubuntu (apt
  only), creates the `opensmart` bridge network, builds the `opensmart/web`
  image from `Containers/build/opensmart/Dockerfile`, and runs it via
  `Containers/run/opensmart/docker-compose.yml` with
  `./opensmart.sh start --bind 0.0.0.0:8000 --prod` as its command. It must
  run as root and is implemented but **has not been executed against a real
  Docker Engine** — it was written and statically reviewed only; verify it
  yourself on a host you're ready to commit to before relying on it.

**Single-port production serving:** `OpenSMART/backend/app/main.py` mounts
`OpenSMART/frontend/dist` as static files (via `fastapi.staticfiles.StaticFiles`,
mounted after all API routes) whenever `frontend/dist/index.html` exists. In
the normal dev workflow that file is never built, so this is inert; `--prod`
mode is what actually builds it.

**Known caveat:** if `OpenSMART/backend/.venv` or `OpenSMART/frontend/node_modules`
already exist from host-side development, delete them before the first
container run — they were built for the host's platform/libc, not the
container's, and their mere presence skips `run_app.sh`'s reinstall step
(the same class of problem hit for real during the Phase 1 directory move,
where a moved `.venv`'s shebangs pointed at a now-nonexistent path).

`Containers/OpenSMART-Standalone/` is the existing reference Docker Compose
bundle for the network-sensor stack (Suricata, Zeek, Arkime, OpenSearch,
WireGuard, OpenVPN, nginx) — a standalone tool users can run and customize
separately, left untouched.

`Containers/build/` and `Containers/run/` hold the per-tool Dockerfiles and
compose files copied from `OpenSMART-Standalone` (`base`, `suricata`, `zeek`,
`wireguard`, `openvpn` — official upstream images like OpenSearch/Arkime/nginx
have none), plus `Containers/build/opensmart/Dockerfile` and
`Containers/run/opensmart/docker-compose.yml` for the main app container
(self-contained image, whole repo bind-mounted at `/opt/opensmart`, no
Linux-user password or sudo — `docker exec` doesn't need one and nothing in
`start --prod` requires root).
