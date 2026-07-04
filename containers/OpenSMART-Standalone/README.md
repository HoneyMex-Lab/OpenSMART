# OpenSMART Framework — Deployment Bundle

Container-based **Network Security Monitoring (NSM)** stack for **Debian 13 + Docker**.
This bundle is a self-contained copy of the OpenSMART template: the image **build tree**
and the **deployment tree**, plus a machine-readable description of the whole project.

> **Heads-up — default credentials:** the Arkime web UI ships with
> **username `admin` / password `changeme`**, and OpenSearch runs with **authentication
> disabled**. See [Credentials & Defaults](#credentials--defaults) and change them before
> any real use.

---

## Contents

```
opensmart-bundle/
├── README.md                     # this file
├── MANIFEST.json                 # deep, machine-readable description of the project
├── opensmart-framework/          # DEPLOY tree (docker compose stacks + deploy.sh)
│   ├── deploy.sh
│   └── containers/<service>/
│       ├── docker-compose.yml
│       └── volumes/data/         # mount point (-> /data), empty in the bundle
└── opensmart-framework-build/    # BUILD tree (Dockerfiles + scripts/templates)
    └── docker-images/<image>/Dockerfile
```

`MANIFEST.json` is the authoritative, parseable source of truth (images, services,
ports, networks, credentials, tuning, build/deploy steps, known issues). This README is
the human-facing companion.

---

## Architecture

| Service        | Image                                   | Network            | Published port | Role |
|----------------|-----------------------------------------|--------------------|----------------|------|
| opensearch     | `opensearchproject/opensearch:2.18.0`   | opensmart (bridge) | `9200/tcp`     | Search/analytics backend for Arkime |
| arkime-capture | `ghcr.io/arkime/arkime/arkime:v6-latest`| **host**           | —              | Full packet capture on `eth0` |
| arkime-viewer  | `ghcr.io/arkime/arkime/arkime:v6-latest`| opensmart (bridge) | `8005/tcp`     | Arkime web UI |
| suricata       | `opensmart/suricata`                    | **host**           | —              | IDS on `eth0` (ET Open rules) |
| zeek           | `opensmart/zeek`                        | **host**           | —              | NSM tool (idle — tool only, no config) |
| wireguard      | `opensmart/wireguard`                   | opensmart (bridge) | `51820/udp`    | WireGuard VPN server |
| nginx          | `nginx:1.27`                            | opensmart (bridge) | `8080/tcp`     | Landing page / reverse-proxy placeholder |
| openvpn        | `opensmart/openvpn`                     | opensmart (bridge) | `1194/udp`\*   | OpenVPN server — **defined, not started** |

\* OpenVPN is only exposed when manually enabled (see [OpenVPN](#openvpn-defined-not-running)).

**Networks**
- **host** — `zeek`, `suricata`, `arkime-capture` (must sniff the host `eth0`).
- **opensmart** — external bridge `172.250.250.0/24` for everything else.

**Volumes** — every service mounts `./volumes/data` → `/data` (pcaps, logs, PKI, keys).

---

## Images

Custom images are layered on a single Debian 13 base:

| Image                 | Base           | Built from                          | Notes |
|-----------------------|----------------|-------------------------------------|-------|
| `opensmart/base`      | `debian:13`    | `docker-images/base`                | Clean base, `ENTRYPOINT bash` |
| `opensmart/zeek`      | `opensmart/base` | `docker-images/zeek`              | Zeek 8.2.0 (OpenSUSE OBS Debian_13 repo); tool only |
| `opensmart/suricata`  | `opensmart/base` | `docker-images/suricata`          | Suricata 7.0.10 + ET Open rules; runs on `eth0` |
| `opensmart/openvpn`   | `opensmart/base` | `docker-images/openvpn`           | OpenVPN 2.6.14 + easy-rsa; hardened config + PKI tooling |
| `opensmart/wireguard` | `opensmart/base` | `docker-images/wireguard`         | wireguard-tools; server keys + client template |

Official images used directly: `opensearchproject/opensearch:2.18.0`,
`ghcr.io/arkime/arkime/arkime:v6-latest`, `nginx:1.27`.

---

## Build

From the build tree:

```bash
cd opensmart-framework-build/docker-images
docker build -t opensmart/base       ./base
docker build -t opensmart/zeek       ./zeek
docker build -t opensmart/suricata   ./suricata
docker build -t opensmart/openvpn    ./openvpn
docker build -t opensmart/wireguard  ./wireguard
```

`opensmart/base` must be built first (the others `FROM opensmart/base`). See
`opensmart-framework-build/README.md` for per-image details and upstream sources.

---

## Deploy

```bash
cd opensmart-framework
SERVER_IP=<server-ip> ./deploy.sh
```

`deploy.sh` is idempotent and performs:

1. Create the external `opensmart` network (if missing).
2. Fix volume permissions (`opensearch/volumes/data` → `1000:1000`).
3. Start **OpenSearch** and wait for it to be healthy.
4. Start **Arkime** capture + viewer. Capture runs `db.pl init --ifneeded` via `docker.sh`;
   the script then waits for the `arkime_users` index and creates the admin user.
5. Start **Suricata, Zeek, WireGuard, nginx**.
6. Generate the **OpenVPN PKI** (`gen-pki.sh`) — the server itself stays **down**.

Per-stack alternative: `cd containers/<service> && docker compose up -d`.

### Verify

```bash
curl -fs http://localhost:9200/_cluster/health                              # -> "status":"green"
curl -fs --digest -u admin:changeme http://localhost:8005/eshealth.json     # -> HTTP 200
curl -fs http://localhost:8080/                                             # -> nginx 200
docker logs opensmart-suricata | grep 'Engine started'
docker exec opensmart-wireguard wg show
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

---

## Credentials & Defaults

> ⚠️ **All of these are insecure placeholders for a test/template deployment. Rotate them before exposing the host.**

### Arkime viewer (web UI)
- **URL:** `http://<host>:8005`
- **Username:** `admin`
- **Password:** `changeme`
- **Role:** admin (created with `--admin`)
- **Auth mode:** HTTP digest
- Created by `deploy.sh`:
  ```
  docker exec opensmart-arkime-viewer \
    /opt/arkime/bin/arkime_add_user.sh admin "Admin User" changeme --admin
  ```
- **Change the password:**
  ```bash
  docker exec opensmart-arkime-viewer \
    /opt/arkime/bin/arkime_add_user.sh admin "Admin User" '<NEW_PASSWORD>' --admin
  ```

### OpenSearch
- **URL:** `http://<host>:9200`
- **Authentication:** **NONE** — the security plugin is disabled (`DISABLE_SECURITY_PLUGIN=true`).
- Anyone who can reach `:9200` has full read/write. **Firewall it** or enable the
  OpenSearch security plugin for production.

### OpenVPN
- **Auth:** certificate + `tls-crypt` key (no username/password).
- Crypto: EC `secp384r1`, SHA512; CA & certs valid **3650 days**.
- Client keys are generated **passwordless** (`build-client-full … nopass`) — protect the
  resulting `.ovpn` files.

### WireGuard
- **Auth:** public/private key pair (no password).
- Server public key: `containers/wireguard/volumes/data/server_public.key` (generated at first run).

### Dropped privileges
- Arkime capture runs as `nobody:daemon`; OpenVPN runtime as `nobody:nogroup`.

> **Secrets are not shipped in this bundle.** PKI, WireGuard keys, pcaps and OpenSearch
> indices are created at deploy time under each service's `volumes/data` and are excluded here.

---

## VPN client creation

### WireGuard
On first start the container writes `wg0.conf`, the server keypair, and a client template
(`client.conf.tmpl`) into `containers/wireguard/volumes/data/`. To add a client:

1. Generate a client keypair: `wg genkey | tee client_priv | wg pubkey > client_pub`.
2. Fill `client.conf.tmpl` (`CLIENT_PRIVATE_KEY`, `Address 10.30.0.X/32`).
3. Append a `[Peer]` block (client public key + `AllowedIPs = 10.30.0.X/32`) to `wg0.conf`
   and reload: `docker exec opensmart-wireguard wg-quick down /data/wg0.conf && wg-quick up /data/wg0.conf` (or restart the container).

VPN subnet: `10.30.0.0/24`, endpoint `:51820/udp`.

### OpenVPN
PKI is generated by `gen-pki.sh`. To emit a self-contained `.ovpn`:

```bash
cd opensmart-framework/containers/openvpn
docker compose run --rm openvpn /opt/opensmart/make-client.sh <client-name> <server-ip>
# -> ./volumes/data/clients/<client-name>.ovpn  (CA/cert/key/tls-crypt inlined)
```

VPN subnet: `10.20.0.0/24`, endpoint `:1194/udp`.

---

## OpenVPN (defined, not running)

The LXC host has **no `/dev/net/tun`**, so the OpenVPN server cannot start. It is kept out
of `docker compose up` via the compose **`manual` profile**. PKI and the hardened
`server.conf` are still generated into `containers/openvpn/volumes/data`.

To actually run it once TUN is available on the Proxmox host:

```yaml
# add to containers/openvpn/docker-compose.yml under the openvpn service:
devices:
  - "/dev/net/tun:/dev/net/tun"
```
```bash
cd opensmart-framework/containers/openvpn
docker compose --profile manual up -d
```

---

## Tuning & environment constraints

Sized for the reference host (**8 GB RAM / 6 vCPU**, Debian 13 LXC):

| Setting                     | Value        | Where |
|-----------------------------|--------------|-------|
| OpenSearch heap             | `-Xms2g -Xmx2g` | `containers/opensearch/docker-compose.yml` |
| Arkime `packetThreads`      | `2`          | `containers/arkime/etc/config.ini` |
| Arkime `pcapBufferSize`     | `33554432` (32 MB) | same |
| Arkime `pcapReadMethod`     | `libpcap`    | same |
| Arkime `snapLen`            | `32768`      | same |

**Constraints that are LXC-level, not RAM-level (do not "fix" by adding memory):**
- **No `/dev/net/tun`** → OpenVPN server can't run.
- **`memlock` ulimit = 8192 bytes** → the AF_PACKET `tpacketv3` ring mmap fails, so Arkime
  uses `libpcap`, and OpenSearch runs with `bootstrap.memory_lock=false`.

---

## Troubleshooting (fixes already applied)

| Symptom | Cause | Fix in this bundle |
|---------|-------|--------------------|
| OpenSearch won't start: `error setting rlimit type 8` | LXC forbids unlimited `memlock` | removed `memlock` ulimit; `bootstrap.memory_lock=false` |
| Arkime capture: `Unknown option --wait-for-db` | `docker.sh` flags placed before `--` | service flags after `--`; init via `--db '… init --ifneeded'` |
| Arkime capture: tpacketv3 mmap failure (128 MB) | AF_PACKET ring blocked by `memlock=8192` | `pcapReadMethod=libpcap` + `pcapBufferSize` |
| Arkime capture FATAL: missing `oui.txt` | enrichment files not bundled in image | removed `ouiFile`/`rirFile` (optional) |
| Arkime: parsers fail to load (`./parsers`) | relative `parsersDir` vs `docker.sh` cwd | absolute `parsersDir`/`pluginsDir` |

To enable GeoIP/OUI enrichment later, run inside the capture container:
`/opt/arkime/bin/arkime_update_geo.sh` (needs internet / a MaxMind license), then set
`ouiFile`/`rirFile`/`geoLite2*` in `config.ini`.

---

## Security checklist before real use

- [ ] Change the Arkime admin password (`admin` / `changeme`).
- [ ] Restrict or authenticate OpenSearch `:9200` (firewall or enable the security plugin).
- [ ] Protect generated VPN client files (passwordless keys).
- [ ] Review exposed ports (`9200`, `8005`, `8080`, `51820/udp`, and `1194/udp` if enabled).
- [ ] Replace the nginx default page with a real config if used as a proxy.

---

*Validated on a lab Debian 13 Docker host. Replace `<server-ip>` with the target
host address before deployment. See `MANIFEST.json` for the full
machine-readable description.*
