# Containers

Docker-related deployment artifacts for OpenSMART and its tool integrations.

- `OpenSMART-Standalone/` — a self-contained reference bundle (build tree +
  deploy tree + `deploy.sh` + `MANIFEST.json`) for users who want to run the
  network-sensor stack (Suricata, Zeek, Arkime, OpenSearch, WireGuard,
  OpenVPN, nginx) manually and customize it independently of the main app.
  Left untouched as a standalone reference tool.
- `build/` — Dockerfiles for the custom images (`base`, `suricata`, `zeek`,
  `wireguard`, `openvpn`), copied from `OpenSMART-Standalone`. Official
  upstream images (OpenSearch, Arkime, nginx) have no local Dockerfile here or
  in `OpenSMART-Standalone`.
- `run/` — one directory per tool/module, each with its own
  `docker-compose.yaml` and a `volumes/data/` directory bind-mounted into the
  container (never a named Docker volume). `run/opensmart/` is the main app
  container: `docker-compose.yml` bind-mounts the whole repo at
  `/opt/opensmart` and runs `./opensmart.sh start --bind 0.0.0.0:8000 --prod`.

`build/opensmart/Dockerfile` and `run/opensmart/docker-compose.yml` are wired
together by `./opensmart.sh install` (root, Debian/Ubuntu only): bootstraps
Docker Engine, creates the `opensmart` network, builds the image, fixes bind-mount
ownership, and starts the container. Once installed, use `./opensmart.sh
start` / `stop` / `status` / `restart` / `recreate` to manage it — see
`docs/architecture.md` for details. `OpenSMART-Standalone/opensmart-framework/deploy.sh`
remains available if you want to run the network-sensor stack independently.
