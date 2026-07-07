# Architecture

OpenSMART is split into a Python backend, a React frontend, and Bash operational hooks. The whole app lives under `opensmart/` at the repo root, alongside a `containers/` tree for Docker-based deployment tooling and a root-level `opensmart.sh` entrypoint.

This document is the human-readable architecture reference. `docs/MANIFEST.json` is the machine-readable companion — the same facts (stack, layout, entrypoints, API surface, configuration, security posture, deployment status) in a structured format meant for tooling and coding agents to parse directly rather than scrape from prose.

Two other technical references cover different depths of the same system: `docs/technical-overview.md` (shorter, request-flow-level summary with a diagram of the container provisioning flow) and `docs/modules-reference.md` (per-module/tool detail: what each one does, its config keys, and its implementation status). `docs/user-guide.md` covers the same ground for a non-technical audience.

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
- `opensmart/frontend/src/components/`: login, forced-password-change, shell, and sidebar components.
- `opensmart/frontend/src/pages/`: OpenSMART modules, tools, account, status, audit, about, WebConsole Config, Tools Config, OpenSMART Config, wizard, and access pages.
- `opensmart/frontend/public/assets/`: local generated SVG assets for tool and summary cards.
- `opensmart/frontend/src/styles.css`: responsive dark theme and layout styles.

## Admin Bootstrap

On backend startup, `init_db()` creates the schema and default records. If no admin user exists, it creates username `admin` with a generated password, prints it once, marks the account as requiring a password change on next login, and marks the install as needing the first-run Wizard — see "Password Policy and Forced Change" and "First-Run Wizard" below.

`opensmart/scripts/run_app.sh` watches backend startup output for the first-run marker and pauses so the operator can save the password before the frontend starts.

## Placeholder Integrations

Placeholder pages remain only for Honeypot, LXC Manager, Graylog and NTOP. Everything else on the Status page shows real container-derived state (see "Status Overview" below). Tool entries use admin-configured internal URLs and load iframe content only after a tool is selected; Wazuh and Arkime get a working local URL prefilled by the Wizard.

## Status Overview (real container state)

`GET /api/provisioning/overview` drives the Status page. For every compose project under `opensmart/containers/run/` (`provisioning.KNOWN_CONTAINERS`, including multi-container projects like arkime and wazuh via `CONTAINER_SERVICES`), `container_overview()` runs `docker inspect` through the socket proxy — EXEC is deliberately blocked there, so inspect output is the richest signal available — and derives per container: status, image tag, uptime (parsed from `State.StartedAt`), restart count, health-check state, and a warnings list (stuck restarting, restart_count > 3, OOM-killed, unhealthy, non-zero exit code). The Status page renders module/tool health from their backing projects (`frontend/src/pages/backing.ts`), lists every provisioned container with expandable warnings, and offers a per-project Restart action (`POST /api/provisioning/restart`, audited). A VPN summary (WireGuard peers from `wg0.conf`, OpenVPN valid/revoked certs from easy-rsa `index.txt`) rides along in the same response.

## Themes

Three UI themes — Dark (default), Classic (light) and Matrix — are implemented by tokenizing every color literal in `frontend/src/styles.css` into CSS variables (`--c-<slug>`) with three generated palette blocks (`:root`, `:root[data-theme="classic"]`, `:root[data-theme="matrix"]`). The Classic palette is a lightness inversion of the dark palette; Matrix maps cool hues to green and adds a monospace font. Selection lives in Configuration → Platform Parameters, persists in the `theme` setting, and is exposed pre-login through `GET /api/settings/public` so the login page renders in the right theme; `App.tsx` stamps `data-theme` on the document root.

## VPN Module

`backend/app/vpn.py` manages OpenVPN/WireGuard server instances as compose projects it generates under `opensmart/containers/run/vpn/<name>/`, registered in the `vpn_instances` table. Each instance publishes its own UDP host port and gets a unique `10.<n>.0.0/24` subnet. Because the socket proxy blocks EXEC, all key/cert crypto runs in one-off containers (`docker run --rm`, the same pattern as `host_interfaces()`): easy-rsa PKI + `make-client.sh` for OpenVPN, `wg genkey` (returned on stdout) for WireGuard. Everything else is direct file work on the bind-mounted `volumes/data/` — note the unprivileged-UID-mapping consequence: one-off container root is a different host UID than the backend, so OpenVPN one-off runs end with `chmod -R a+rwX /data` and WireGuard key files are written by the backend itself (the host path above the mount stays root-only). User lifecycle: create (client config downloadable through the API), expiry visible from `index.txt`, revoke (CRL regen for OpenVPN — re-read per handshake, no restart; peer-block removal + restart for WireGuard). OpenVPN instances can additionally authenticate against LDAP/Samba AD (`auth_mode=ldap`, openvpn-auth-ldap plugin — requires the image rebuilt via `opensmart.sh`). OpenVPN needs `/dev/net/tun` on the Docker host; without it, start fails with a clear daemon error surfaced in the UI. All routes are admin-only and audited (`/api/vpn/*`).

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
  container — not the image, network, or the bind-mounted app data),
  **rebuilds the `opensmart/web` image from the current source and
  Dockerfile** (normal Docker layer caching applies — fast if nothing
  actually changed), and creates a fresh container from the rebuilt image,
  then runs the integrity check. Skips the confirmation (nothing to remove)
  if no container exists yet. The rebuild step is not optional: without it,
  `recreate` would silently keep running whatever image was already tagged
  `opensmart/web` even after a `git pull` brought in Dockerfile changes —
  confirmed on the reference host as the actual reason a Dockerfile fix appeared
  not to take effect after "cloning the repo after fixes and running
  again" (recreate, not a full `install`, was what picked the code back up).
- `./opensmart.sh uninstall` asks for confirmation (must type `UNINSTALL`),
  then runs `docker compose down` in every directory under
  `opensmart/containers/run/` that has a `docker-compose.yml` — the main app
  + `docker-socket-proxy`, and any tool container ever started (Suricata,
  Zeek, Arkime, OpenSearch, WireGuard, OpenVPN; `openvpn` specifically with
  `--profile manual`, since its service is profile-gated). Deliberately
  narrow in scope: it does not remove the `opensmart` Docker network,
  container images, or bind-mounted application data (SQLite DBs, logs) —
  only containers. Full command output goes to `logs/uninstall.log`.
- **Integrity check** (shared by `start`'s container path, `restart`, and
  `recreate`): first confirms the container reaches a stable running
  state (same stability logic `install` uses — tolerant of the brief
  "running" window a crash-looping container can show between restarts),
  then polls `/api/health` on the container's published port (resolved via
  `docker port`, not assumed) for up to 5 minutes, since a cold start needs
  to `uv sync`/`npm install`/`npm run build` inside the container first.
- `./opensmart.sh install` first checks that every ancestor directory of the
  checkout is traversable by the container's non-root user (the "other"
  execute bit) — installing under `/root` (mode `700`) is the common way to
  fail this, and fails clearly here rather than as an opaque crash loop
  later (confirmed twice against a real Docker Engine before this check
  existed: the container starts, but its own entrypoint gets "Permission
  denied" trying to run anything inside the bind mount, because chowning the
  checkout itself — see below — doesn't help when a directory *above* it
  blocks traversal). It then bootstraps Docker Engine on Debian/Ubuntu (apt
  only), creates the `opensmart` bridge network, builds the `opensmart/web`
  image from `containers/build/opensmart/Dockerfile`, chowns the bind-mounted
  app directory to uid 1000 (the container's non-root `opensmart` user; a
  root-owned checkout otherwise leaves the container unable to create
  `.venv`/`node_modules`/the SQLite DBs) — and, since that chown is exactly
  what makes a later `git pull` (typically run as root, to fetch updates)
  fail with "detected dubious ownership", also registers the checkout as a
  `git config --global --add safe.directory` exception in root's gitconfig
  so upgrading via `git pull` doesn't require the operator to work that out
  themselves — and runs it via
  `opensmart/containers/run/opensmart/docker-compose.yml` with
  `./opensmart.sh start --bind 0.0.0.0:8000 --prod` as its command. It must
  run as root. **Verified against a real Docker Engine** on a Debian 13 test
  host: a fresh install ends with a stable container serving `/api/health`
  and the built frontend, and the initial admin password extracted from
  `docker logs`. A cold install (no cached `.venv`/`node_modules`) can take a
  few minutes to build the frontend and sync backend dependencies inside the
  container before it's reachable — on a host with slow/unreliable network
  access to PyPI (backend deps) or npm, this can crash-loop for well past
  the 5-minute password-reveal window (confirmed on the same reference host under
  degraded network conditions). The Dockerfile sets
  `UV_PYTHON_PREFERENCE=only-system` so `uv` uses the apt-installed
  `python3` (already 3.13.x on Debian 13) instead of also trying to
  download its own managed Python build from astral's CDN on every cold
  start — that download was a second, avoidable point of failure on the
  same flaky network (confirmed: it reliably reproduced `[FAIL] Python
  3.13 available (not found via uv)` in the pre-start health check).
  Backend *package* installation (`fastapi`, `uvicorn`, etc., still via
  PyPI) is unaffected by this and can still stall on a sufficiently broken
  network the *first* time — that part has no way around genuinely needing
  to fetch those packages once. What *is* fixed: `UV_CACHE_DIR` points at
  `.uv-cache/` inside the already bind-mounted project directory (no
  separate volume needed) instead of uv's default location in the
  container's own ephemeral home directory, so a successful download
  persists on the host and survives container recreation — a flaky network
  only has to cooperate once, ever, not on every single recreate/reinstall.
  `install` only prints the final "✔ running"
  banner if it actually confirmed the first-run marker in time; otherwise it
  exits non-zero with a `docker ps`/`docker logs` pointer instead of
  claiming success.

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
an explicit allowlist (`CONTAINERS`, `NETWORKS`, `IMAGES`, `VOLUMES`, `POST`
only — no `EXEC`, `BUILD`, `SWARM`, `SECRETS`, `SERVICES`, `PLUGINS`,
`CONFIGS`, `SESSION`, `DISTRIBUTION`, `SYSTEM`, `AUTH`; `VOLUMES` is on
because `docker compose` queries the `/volumes` API as part of normal project
reconciliation even for bind-mount-only projects — confirmed via the proxy's
own access logs during live testing, not a guess), and the `opensmart`
service's `DOCKER_HOST` points at it. The backend shells out to
`docker compose -f <path> up -d`/`down` against that restricted endpoint,
allowlisted to the container names that actually exist under
`opensmart/containers/run/` (`KNOWN_CONTAINERS` in `provisioning.py`) — never
an arbitrary path. `MODULE_CONTAINERS`/`TOOL_CONTAINERS` in that file map
OpenSMART modules/tools to the container(s) they need, and explicitly report
"no template yet" for the ones with no container (Wazuh-backed modules,
Graylog) rather than silently no-op'ing. See `docs/technical-overview.md`
for a diagram of this flow and its security model.

**Verified against a real Docker Engine** (not just typecheck/lint): built
the `opensmart/base` and `opensmart/suricata` images, started/stopped
Suricata through `/api/provisioning/start`/`stop` with `docker ps` confirming
actual container state, and exercised the module-level path (`kind:
"module"`) that the Wizard and the Network IDS toggle actually use. That
test surfaced and fixed three real issues: the app container's own
entrypoint (`opensmart.sh start`) initially saw itself as "an existing
opensmart container" once it gained Docker access and tried to manage
itself instead of starting the app (fixed with a `/.dockerenv` check that
only applies the host/container-detection branch on the actual host); the
mount had to anchor at the repo root, not just `opensmart/`, since
`opensmart.sh` itself lives one level up; and the proxy's allowlist needed
`VOLUMES=1` (see above).

## Password Policy and Forced Change

- `users.must_change_password` (added via `ALTER TABLE`) is set whenever a
  password is set *for* a user rather than *by* them: the bootstrap admin
  account, a brand-new user an admin creates, an admin resetting another
  user's (or their own) password, and the CLI `reset-admin-password`/
  `full-reset` paths. It is cleared when the user changes their own password
  via `POST /api/account/password`.
- Enforced server-side, not just in the UI: `security.require_csrf()` (used
  by every mutating route) returns `423 Locked` while the flag is set,
  except for `/api/auth/me`, `/api/auth/logout`, and
  `/api/account/password` — just enough surface for the user to identify
  themselves, fix their password, or log out. The frontend renders a
  blocking `ForceChangePasswordPage` in the same situations.
- A configurable complexity policy (`password_policy` setting: `strict`
  [default] / `moderate` / `low` / `disabled`) is enforced by
  `security.validate_password_complexity()` on every user-supplied password
  (account self-service, admin-created users, admin password resets — not
  the CLI's own randomly-generated reset passwords, which are always
  complex enough by construction). The Settings UI shows a red warning
  banner when `low`/`disabled` is selected.
- The two previously-duplicated password-hashing code paths (`routes/*.py`
  vs. the CLI's direct `argon2` calls in `admin_tools.py`) are now one
  shared helper, `security.set_user_password()`.

## First-Run Wizard

- A global `wizard_completed` setting (default `"true"` for
  existing/upgraded installs) is set to `"false"` only by `bootstrap_admin()`
  — i.e. only on a genuinely fresh install with no admin user yet — so it
  never retroactively appears after an upgrade.
- After the bootstrap admin's forced password change, `App.tsx` renders
  `WizardPage.tsx` instead of the normal app shell while
  `wizard_completed !== 'true'` and the logged-in user is an admin.
- Four steps:
  1. **Basics** — application name and optional logo (the running
     version/build is shown with a pointer to `./opensmart.sh install`
     for updates; there is still no auto-updater).
  2. **Network** — real host NICs enumerated via
     `GET /api/provisioning/host-interfaces` (a one-off busybox container
     on the host network, 60 s cached; physical interfaces listed first,
     virtual ones behind a toggle, manual comma-separated entry as a
     fallback). The selection persists as the `monitor_interfaces`
     setting and is injected into the Suricata compose file as
     `CAPTURE_IFACES` on start, producing one `-i <iface>` per interface.
  3. **Modules & Tools** — card toggles with recommended defaults
     pre-selected on a fresh install (Suricata/Zeek traffic monitoring,
     Suricata IDS with `eve_source=native`, OpenVPN access, embedded
     Wazuh/Arkime/Proxmox). Enabling a Wazuh-backed module auto-enables
     the Wazuh tool (and disabling Wazuh auto-disables its dependents),
     with visible notices; a VPN type selector chooses OpenVPN (default)
     or WireGuard.
  4. **Provision** — a sequential runner with three phases
     (Configuration, Services, Finalize), a progress bar, per-service
     ok/warning/error rows including container-level failure details,
     and a final summary. Wazuh/Arkime iframe URLs are prefilled when
     empty. `wizard_completed` flips to `true` only in the Finalize
     phase, and the app shell is entered explicitly afterwards so the
     summary stays visible.

## Network IDS: Native vs. External eve.json

- The Network IDS module's config gained an `eve_source` field
  (`external` [default, preserves existing installs] / `native`).
- Path resolution is centralized in `eve_ingest.resolve_eve_json_path()`:
  `native` returns the bundled Suricata container's known output location
  (`NATIVE_SURICATA_EVE_PATH`, computed from `opensmart/containers/run/suricata`'s
  bind mount), anything else returns the manually-configured
  `eve_json_path`. Both the API-facing config (`network_ids.ids_config()`)
  and the ingestion engine (`eve_ingest.shared_config()`) call it — they
  previously resolved the path independently, and the ingestion side
  ignored `eve_source` entirely, so native mode looked configured in the
  UI while ingesting nothing. The OpenSMART Config UI shows a live
  Start/Stop/status control for the Suricata container in native mode,
  backed by the provisioning engine above.
