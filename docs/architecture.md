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

- `./opensmart.sh start [--bind ADDRESS:PORT] [--prod]` behaves differently
  depending on whether an `opensmart` container already exists (i.e.
  `install` has been run before):
  - **Container exists:** `--bind`/`--prod` are ignored (with a note printed
    explaining why — the container's bind address is fixed by
    `opensmart/containers/run/opensmart/docker-compose.yml`). If the container isn't
    already running, starts it (`docker compose start`); either way, then
    runs the same integrity check `restart`/`recreate` use (see below).
  - **No container:** runs directly on the host via
    `opensmart/scripts/run_app.sh start --host ADDRESS --port PORT [--prod]`,
    defaulting to `--bind 0.0.0.0:8000` when `--bind` is omitted. Without
    `--prod`, this starts the backend (`uvicorn`) on that address/port and
    the frontend dev server on `5173`. With `--prod`, it builds the frontend
    once (`npm run build`) instead of starting the Vite dev server, skips
    the interactive first-run password-reveal prompt, and lets the backend
    serve the built frontend itself (see below) — this is the mode the
    container entrypoint uses.
- `./opensmart.sh restart` runs `docker compose restart` then the same
  integrity check as `start`'s container path. Errors clearly if no
  container exists yet.
- `./opensmart.sh recreate` asks for confirmation (must type `RECREATE`),
  then removes the existing container (`docker compose rm -f -s`, only the
  container — not the image, network, or the bind-mounted app data) and
  creates a fresh one from the current `opensmart/web` image, then runs the
  integrity check. Skips the confirmation (nothing to remove) if no
  container exists yet.
- **Integrity check** (shared by `start`'s container path, `restart`, and
  `recreate`): first confirms the container reaches a stable running
  state (same stability logic `install` uses — tolerant of the brief
  "running" window a crash-looping container can show between restarts),
  then polls `/api/health` on the container's published port (resolved via
  `docker port`, not assumed) for up to 5 minutes, since a cold start needs
  to `uv sync`/`npm install`/`npm run build` inside the container first.
- `./opensmart.sh install` bootstraps Docker Engine on Debian/Ubuntu (apt
  only), creates the `opensmart` bridge network, builds the `opensmart/web`
  image from `containers/build/opensmart/Dockerfile`, chowns the bind-mounted
  app directory to uid 1000 (the container's non-root `opensmart` user; a
  root-owned checkout otherwise leaves the container unable to create
  `.venv`/`node_modules`/the SQLite DBs), and runs it via
  `opensmart/containers/run/opensmart/docker-compose.yml` with
  `./opensmart.sh start --bind 0.0.0.0:8000 --prod` as its command. It must
  run as root. **Verified against a real Docker Engine** on a Debian 13 test
  host: a fresh install ends with a stable container serving `/api/health`
  and the built frontend, and the initial admin password extracted from
  `docker logs`. A cold install (no cached `.venv`/`node_modules`) can take a
  few minutes to build the frontend and sync backend dependencies inside the
  container before it's reachable.

**Install output:** `install` prints one line per main step (root check,
distro detection, Docker Engine install, network creation, image build,
ownership fix, container start, stability check, readiness/password wait) —
shows a banner (Mizton Labs & Honeynet Mexico Team attribution, ASCII honeycomb logo)
first. Full command output (apt-get, docker build, docker compose) is not
shown on the terminal — it goes only to `logs/install.log`, which is created
fresh on every run. On failure, the current step line is closed with
"failed" and the error points at that log file.

- `./opensmart.sh stop` runs `docker compose stop` in
  `opensmart/containers/run/opensmart/` (stops the container without removing it —
  `docker compose start` brings it back). No-op with a clear message if the
  container doesn't exist or is already stopped.
- `./opensmart.sh status` reports two independent things: the Docker
  container's own state (`docker inspect`'s `State.Status` and
  `RestartCount` — running/restarting/exited/not found) and, only when the
  container is running, whether the application inside it is actually
  responding (`curl .../api/health` against the container's published
  port, resolved via `docker port` rather than assumed). A running container
  with an unreachable app (still starting, or crashed) is reported
  distinctly from a genuinely healthy one.

**App-level CLI (`opensmart/scripts/run_app.sh`):** `opensmart.sh`'s
container/host branching for `start` sits on top of `run_app.sh`, which has
its own consistent subcommand set — `start`, `stop`, `status`, `restart`,
`reset-admin-password`, `reset-data-all`, `reset-data-ids`,
`reset-data-network`, `reset-all`, `health` — mirroring `opensmart.sh`'s
naming (no more `--flag` forms, and no implicit default command; a bare
invocation now errors with usage, same as `opensmart.sh`). `start`/`restart`
write `opensmart/logs/run_app.state` (PID, bind host/port, prod mode) once
the backend is confirmed alive, so a separate later invocation of
`status`/`stop`/`restart` — including `docker exec <container>
./opensmart/scripts/run_app.sh status` — can find and act on the running
instance; `restart` reuses the previous bind/mode from that file unless
explicitly overridden. `opensmart.sh reset-admin-password` /
`reset-data-all` / `reset-data-ids` / `reset-data-network` / `reset-all` /
`health` forward to the same-named `run_app.sh` subcommand — inside the
container (`docker exec`) if one exists, or directly on the host
otherwise — so these no longer require knowing about `run_app.sh` at all.

Two consistency fixes on that forwarding path:
- `run_app.sh`'s `reset-*` subcommands ask for a typed confirmation via
  `read -p`, and bash only *prints* that prompt when stdin is an actual
  terminal — `docker exec -i` alone (no `-t`) keeps stdin open for input but
  allocates no pseudo-TTY, so the prompt was silently invisible (though
  still functionally read) when going through the container. `opensmart.sh`
  now adds `-t` too, but only when its own stdin is a real terminal
  (`[[ -t 0 ]]`) — `-it` unconditionally would instead error ("not a TTY")
  for piped/scripted invocations.
- `run_app.sh`'s own post-action messages (e.g. "Run ./scripts/run_app.sh
  start to start OpenSMART.") used to always name itself, even when invoked
  through the `opensmart.sh` wrapper — confusing, since
  `./scripts/run_app.sh` isn't a command `opensmart.sh` exposes.
  `RUN_APP_INVOKE_AS` (env var, default `./opensmart/scripts/run_app.sh`)
  controls this self-reference; `opensmart.sh` sets it to `./opensmart.sh`
  (exported for host-mode invocations, passed via `docker exec -e` for the
  container) so these messages point at whichever entrypoint was actually
  used.

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

`containers/build/` holds the per-tool Dockerfiles copied from
`OpenSMART-Standalone` (`base`, `suricata`, `zeek`, `wireguard`, `openvpn` —
official upstream images like OpenSearch/Arkime/nginx have none), plus
`containers/build/opensmart/Dockerfile` for the main app container
(self-contained image; no Linux-user password or sudo — `docker exec` doesn't
need one and nothing in `start --prod` requires root). `containers/build/`
stays at the repo root — these are build-time templates, not tied to a
specific running instance.

`opensmart/containers/run/` holds the actual compose files that get started —
`arkime`, `nginx`, `opensearch`, `opensmart` (the main app),
`openvpn`, `suricata`, `wireguard`, `zeek` — one per service, mostly
bind-mounting `./volumes/data`. This lives *inside* `opensmart/` (not at the
repo root, unlike `containers/build/`) so it's covered by the same host-path
mount as the rest of the app.

**Host-path parity, not `/opt/opensmart`:** the `opensmart` service in
`opensmart/containers/run/opensmart/docker-compose.yml` mounts the project's
`opensmart/` directory at the *same absolute path* inside the container as it
has on the host (via `OPENSMART_PROJECT_DIR`, exported by `opensmart.sh`
before every `docker compose` invocation — see its definition near the top of
the script), instead of remapping to a fixed path like `/opt/opensmart`. This
matters because the backend's provisioning module (`app/provisioning.py`)
runs `docker compose` for sibling containers (Suricata, Zeek, Arkime, ...)
*from inside* the `opensmart` container, but those commands are executed by
the *host's* Docker daemon (reached through the `docker-socket-proxy` sidecar
— see below). Bind-mount sources in `opensmart/containers/run/*/docker-compose.yml`
(e.g. `./volumes/data`) are resolved to absolute paths by the `docker compose`
CLI based on where *it* sees the compose file, then applied by the host
daemon against *its own* filesystem — so those paths only resolve correctly
if the container's view of `opensmart/` matches the host's. Running
`docker compose` manually (not via `opensmart.sh`) requires exporting
`OPENSMART_PROJECT_DIR` yourself first.

**Container provisioning (`app/provisioning.py` + `routes/provisioning.py`):**
the app container does not mount `docker.sock` directly. Instead,
`opensmart/containers/run/opensmart/docker-compose.yml` runs a
`docker-socket-proxy` sidecar (holds the real socket, mounted read-only) with
an explicit allowlist (`CONTAINERS`, `NETWORKS`, `IMAGES`, `POST` only — no
`EXEC`, `BUILD`, `SWARM`, `VOLUMES`, `SECRETS`, etc.), and the `opensmart`
service's `DOCKER_HOST` points at it. The backend shells out to
`docker compose -f <path> up -d`/`down` against that restricted endpoint,
allowlisted to the container names that actually exist under
`opensmart/containers/run/` (`KNOWN_CONTAINERS` in `provisioning.py`) — never
an arbitrary path. `MODULE_CONTAINERS`/`TOOL_CONTAINERS` in that file map
OpenSMART modules/tools to the container(s) they need, and explicitly report
"no template yet" for the ones with no container (Wazuh-backed modules,
Graylog) rather than silently no-op'ing.
