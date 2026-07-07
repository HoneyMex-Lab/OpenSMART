# Modules and Tools Reference

Detailed, per-item reference for every OpenSMART module and every Tool: what it's supposed to do, what's actually implemented today, its configuration keys, and — where relevant — which container backs it and how that container gets started. For the higher-level "how does this all fit together" picture, see `docs/technical-overview.md`. For the settings-table view of the same configuration keys, see `docs/configuration.md`.

Two separate catalogs exist in the app and the database: **OpenSMART Modules** (`opensmart_modules` table, managed at `Settings > OpenSMART Modules`) and **Tools** (`modules` table, managed at `Settings > Tools`). Both share the same underlying shape — `id`, `name`, `description`, `enabled`, `config` (a JSON string) — but represent different things: modules are platform capabilities built into OpenSMART itself; tools are links to (or managed instances of) separate external products.

---

## OpenSMART Modules

### Threat Detection Alerts

- **Purpose:** Summary/triage view of threat detection alerts.
- **Status:** Page content is still placeholder, but the module is now backed by real containers: provisioning it starts the Wazuh stack, and the Status page reports its real container state.
- **Container backing:** Wazuh (`opensmart/containers/run/wazuh/` — official wazuh-docker v4.14.6 images: manager, indexer on host port 9201, dashboard on 443, plus a one-shot cert generator). Data from Wazuh is not yet ingested into this page.
- **Config keys:** None specific yet.

### Network Traffic Monitoring

- **Purpose:** Visibility into network traffic events (DNS, HTTP, TLS, flow, file transfers, and more) extracted from Suricata `eve.json` (shared with the Network IDS module) or, in the future, Zeek JSON logs.
- **Status:** Live — real ingestion and an analysis UI (`NetworkTrafficPage.tsx`), backed by `network_traffic.py`.
- **Container backing:** Indirectly, through whichever eve.json source the Network IDS module is configured to use (see below) when `log_source` is `eve_json`; a future `zeek_json` source would run through Zeek (`opensmart/containers/run/zeek/`), whose ingestion is not implemented yet. Provisioning this module starts both `suricata` and `zeek`.
- **Config keys** (in `opensmart_modules.config` for this row):
  - `log_source`: `eve_json` (default, reuses the Network IDS module's configured eve.json — requires that module enabled) or `zeek_json` (future; requires `zeek_json_path`).
  - `zeek_json_path`: path to a Zeek JSON log file. Not yet consumed by ingestion.
  - `index_dns`, `index_http`, `index_tls`, `index_flow`, `index_fileinfo`, `index_smb`, `index_other_app_layer`, `index_all_suricata_protocols`: per-event-family indexing toggles. The first four default on; the rest default off. `index_all_suricata_protocols` overrides the individual toggles.
  - `exclude_event_types`: JSON array of event-type strings to exclude from the "all protocols" catch-all (defaults to `["stats","drop","internal","pcap"]`).
  - `retention_enabled`, `retention_days`, `retention_time`: automatic data retention, same pattern as Network IDS below.

### Network IDS

- **Purpose:** Suricata-based intrusion detection: alert search/analysis, severity/category breakdowns, an attack map, critical-alert tracking.
- **Status:** Live — the most fully-built module, backed by `network_ids.py` and `NetworkIdsPage.tsx`.
- **Container backing:** Suricata (`opensmart/containers/run/suricata/`), *if* `eve_source` is set to `native`. Provisioning this module starts `suricata`.
- **Config keys** (in `opensmart_modules.config` for this row):
  - `eve_source`: `external` (default — point at an eve.json produced by a Suricata instance you manage yourself) or `native` (use the bundled Suricata container; the eve.json path is then derived automatically, and the OpenSMART Config UI shows a live Start/Stop/status control for that container — see `docs/technical-overview.md`).
  - `eve_json_path`: manually-entered path, only used/editable when `eve_source` is `external`.
  - `summary_refresh_minutes`: how often cached summary data is considered stale (default `5`).
  - `initial_ingestion_gb`: how much of an existing large eve.json to ingest on first run before switching to incremental tailing (`0` = ingest everything, can be slow on large files).
  - `default_top_n`, `analysis_page_size`, `details_page_size`, `details_max_rows`: pagination/sizing knobs for the analysis and details views.
  - `geoip_db_path`: optional path to a MaxMind GeoLite2 City `.mmdb` file, enabling the attack map's geolocation. Not bundled — download separately.
  - `keep_empty_alerts`: whether to keep eve.json `alert`-typed events that lack a `signature_id` (internal/stats noise). Default off (dropped).
  - `index_payload_printable`: whether decoded payload text is stored and searchable at ingest time, vs. decoded on demand at query time (smaller DB, slower search) when off. Default on.
  - `fast_alert_prefilter`: cheap string-match pre-check before full JSON parsing, to skip non-alert lines faster. Default on; only disable for non-standard eve.json formatting.
  - `track_critical_alerts`: `off` (default) / `simple` / `full` — whether and how new critical alerts are tracked as "unseen" until acknowledged.
  - `retention_enabled`, `retention_days` (default `90`), `retention_time` (default `02:00`): automatic daily cleanup of data older than the retention window.

### Endpoint

- **Purpose:** Endpoint monitoring.
- **Status:** Page content is still placeholder; backed by the Wazuh containers (same as Threat Detection Alerts).
- **Container backing:** Wazuh (`opensmart/containers/run/wazuh/`).
- **Config keys:** None specific yet.

### Vulnerability Management

- **Purpose:** Vulnerability tracking.
- **Status:** Page content is still placeholder; backed by the Wazuh containers (same as Threat Detection Alerts).
- **Container backing:** Wazuh (`opensmart/containers/run/wazuh/`).
- **Config keys:** None specific yet.

### Honeypot

- **Purpose:** Honeypot telemetry.
- **Status:** Not supported yet. Planned to be backed by T-Pot in a future release.
- **Container backing:** None.
- **Config keys:** None.

### Access VPN

- **Purpose:** Remote access via VPN — a full management UI for OpenVPN/WireGuard server instances.
- **Status:** Live — `VpnPage.tsx` backed by `backend/app/vpn.py` and `/api/vpn/*`. Create instances (type, UDP port, auth mode), start/stop/restart/delete them, and manage users per instance: create (downloadable client config), see certificate expiry, revoke (OpenVPN CRL / WireGuard peer removal).
- **Container backing:** Generated per-instance compose projects under `opensmart/containers/run/vpn/<name>/` using the `opensmart/openvpn` and `opensmart/wireguard` images. Each instance gets its own UDP host port and a unique `10.<n>.0.0/24` subnet. OpenVPN instances need `/dev/net/tun` on the Docker host (LXC hosts must pass it through); starting one without it fails with the daemon error shown in the UI. The legacy single `openvpn`/`wireguard` compose projects remain for manual use.
- **Config keys** (module row): `vpn_type` — default VPN type chosen in the Wizard (`openvpn` default, `wireguard`). Per-instance settings (port, subnet, `auth_mode` `certs`/`ldap`, LDAP details) live in the `vpn_instances` table, not the module config. LDAP auth (OpenVPN only) uses the openvpn-auth-ldap plugin — added to the image, so run `./opensmart.sh install` (or rebuild) to pick it up.

### LXC Manager

- **Purpose:** Container/VM management (Proxmox LXC).
- **Status:** Not supported yet. Planned for a future release.
- **Container backing:** None.
- **Config keys:** None.

---

## Tools

Tools are managed at `Settings > Tools`. Each has an `enabled` flag and, for iframe-based tools, an internal URL setting (`tool_url_<name>`, see `docs/configuration.md`) shown as an embedded iframe once a user clicks the tool's card in the sidebar/summary.

### Arkime

- **Purpose:** Full packet capture and search (traffic tool).
- **Status:** Iframe-based tool (loads an externally-reachable Arkime viewer URL once configured); the underlying capture+viewer containers are real and provisionable.
- **Container backing:** `arkime` (`opensmart/containers/run/arkime/`, two services: `capture` and `viewer`) plus its dependency `opensearch` (`opensmart/containers/run/opensearch/`). Provisioning the "Arkime" tool starts `opensearch` first, then `arkime`.
- **Config keys:** `tool_url_arkime` (the viewer's URL, e.g. `http://localhost:8005` if using the bundled viewer container's published port).

### OPNsense

- **Purpose:** Firewall management (link only — not something OpenSMART installs or runs).
- **Status:** Iframe-based tool pointing at an OPNsense instance you already manage.
- **Container backing:** None — not installable through this app.
- **Config keys:** `tool_url_opnsense`.

### Proxmox

- **Purpose:** Cluster/asset management (link only).
- **Status:** Iframe-based tool pointing at a Proxmox instance you already manage.
- **Container backing:** None — not installable through this app.
- **Config keys:** `tool_url_proxmox`.

### Wazuh

- **Purpose:** SIEM/endpoint monitoring.
- **Status:** Iframe-based tool entry exists, but there is no container template for Wazuh in this repo yet — provisioning it reports "no template available."
- **Container backing:** None yet.
- **Config keys:** `tool_url_wazuh`.

### Graylog

- **Purpose:** Log management.
- **Status:** Iframe-based tool entry exists, but there is no container template for Graylog yet ("no template yet, needs to be built" per the original requirement) — provisioning it reports "no template available."
- **Container backing:** None yet.
- **Config keys:** `tool_url_graylog`.

---

## Provisioning Summary Table

What actually happens when you enable each item and the Wizard (or a manual toggle) tries to provision it:

| Module / Tool | Container(s) started | Template exists? |
|---|---|---|
| Threat Detection Alerts | — | No (Wazuh) |
| Network Traffic Monitoring | `suricata`, `zeek` | Yes |
| Network IDS | `suricata` (only if `eve_source: native`) | Yes |
| Endpoint | — | No (Wazuh) |
| Vulnerability Management | — | No (Wazuh) |
| Honeypot | — | No (T-Pot, future) |
| Access VPN | `openvpn`, `wireguard` | Yes |
| LXC Manager | — | No (future) |
| Arkime (tool) | `opensearch` (dependency), `arkime` | Yes |
| OPNsense (tool) | — | Not applicable (link only) |
| Proxmox (tool) | — | Not applicable (link only) |
| Wazuh (tool) | — | No |
| Graylog (tool) | — | No |
