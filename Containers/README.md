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
  container (never a named Docker volume). Includes an `opensmart/`
  placeholder for the main app container, not yet built out.

`build/` and `run/` are not yet wired together by any script — that is planned
for `opensmart.sh --install`, which is not implemented yet. Until then, use
`OpenSMART-Standalone/opensmart-framework/deploy.sh` directly if you want to
run this stack.
