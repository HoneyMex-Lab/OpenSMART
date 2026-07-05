# Containers

Docker-related deployment artifacts for OpenSMART and its tool integrations.

- `OpenSMART-Standalone/` — a self-contained reference bundle (build tree +
  deploy tree + `deploy.sh` + `MANIFEST.json`) for users who want to run the
  network-sensor stack (Suricata, Zeek, Arkime, OpenSearch, WireGuard,
  OpenVPN, nginx) manually and customize it independently of the main app.
  Left untouched as a standalone reference tool.
- `build/` — Dockerfiles for the custom images (`base`, `suricata`, `zeek`,
  `wireguard`, `openvpn`, `opensmart`), copied from `OpenSMART-Standalone`.
  Official upstream images (OpenSearch, Arkime, nginx) have no local
  Dockerfile here or in `OpenSMART-Standalone`. Stays at the repo root —
  these are build-time templates, not tied to a running instance.

`../opensmart/containers/run/` (inside the `opensmart/` app directory, not
here) holds the actual compose files that get started — one directory per
tool/module, each with its own `docker-compose.yml` and a `volumes/data/`
directory bind-mounted into the container (never a named Docker volume, and
never a path outside the project). `run/opensmart/` is the main app
container: its `docker-compose.yml` mounts the project's `opensmart/`
directory at the *same absolute path* inside the container as on the host
(host-path parity via `OPENSMART_PROJECT_DIR`, not a fixed `/opt` path — see
`docs/architecture.md`) and runs `./opensmart.sh start --bind 0.0.0.0:8000
--prod`. It also runs a `docker-socket-proxy` sidecar (restricted allowlist,
no raw `docker.sock` mount into the app container itself) so the backend can
start/stop the other tool containers here for the Wizard installer and the
Network IDS native-Suricata toggle.

`build/opensmart/Dockerfile` and `../opensmart/containers/run/opensmart/docker-compose.yml`
are wired together by `./opensmart.sh install` (root, Debian/Ubuntu only):
bootstraps Docker Engine, creates the `opensmart` network, builds the image,
fixes bind-mount ownership, and starts the container. Once installed, use
`./opensmart.sh start` / `stop` / `status` / `restart` / `recreate` to manage
it — see `docs/architecture.md` for details.
`OpenSMART-Standalone/opensmart-framework/deploy.sh` remains available if you
want to run the network-sensor stack independently.
