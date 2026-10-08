# Security Notes

This project includes basic local security controls suitable for a v0.3 beta. Review and harden before production use.

## Passwords

- Password hashes use Argon2 through `argon2-cffi`.
- Plaintext passwords are never stored in SQLite.
- First-run and reset passwords are printed once to the terminal.
- Reset passwords are not written to logs.
- All password-setting code paths (self-service, admin-created users, admin
  resets, the CLI) go through one shared helper,
  `security.set_user_password()`, instead of separate duplicated hashing
  logic.

## Password Complexity Policy

A configurable policy (the `password_policy` setting) governs every
user-supplied password (self-service change, admin-created user, admin
password reset):

| Policy | Requirement |
|---|---|
| `strict` (default) | 12+ characters, 4 of: lowercase/uppercase/digit/symbol |
| `moderate` | 10+ characters, 3 of the 4 character classes |
| `low` | 8+ characters, no class requirement |
| `disabled` | effectively no requirement |

The CLI's own randomly-generated reset passwords (`reset-admin-password`,
`full-reset`) are not subject to this check — they're always complex enough
by construction. Selecting `low` or `disabled` shows a red warning banner in
the settings UI. Changing the policy still goes through the normal
admin-only, CSRF-protected, audited settings save — there's no way to lower
it silently outside that path.

## Forced Password Change

`users.must_change_password` is set to true whenever a password is *set for*
a user rather than chosen *by* them: first-run bootstrap, an admin creating a
new user, an admin resetting another user's (or their own) password, and the
CLI `reset-admin-password`/`full-reset`. It's cleared only by the user
themselves via `POST /api/account/password`.

This is enforced server-side, not just hidden in the UI: while the flag is
set, `security.require_csrf()` — the dependency used by essentially every
mutating route — returns `423 Locked` for anything except `/api/auth/me`,
`/api/auth/logout`, and `/api/account/password`. A determined caller hitting
the API directly cannot bypass this by skipping the frontend. The frontend
separately renders a blocking password-change screen for the same condition.

Admin-triggered resets (via `PUT /api/users/{user_id}` or the CLI) also
invalidate the affected user's existing sessions, so an old session can't
keep operating under a password that's about to be replaced.

## First-Run Admin

When no admin exists, backend startup creates username `admin` with a generated password. `opensmart/scripts/run_app.sh` (invoked via `opensmart.sh start`) pauses after this password is printed so the operator can save it before the frontend starts.

## Admin Password Reset

Run:

```bash
./opensmart/scripts/run_app.sh reset-admin-password
```

The script requires typing `RESET`. A successful reset:

- updates the `admin` user's password hash
- deletes existing sessions for that user
- prints the new password once
- logs action metadata to `logs/opensmart.log`

The log entry includes timestamp, action name, and username only.

## Sessions

- Session tokens are generated with `secrets.token_urlsafe`.
- Session tokens are stored server-side in SQLite.
- The browser receives an HTTP-only `opensmart_session` cookie.
- Session TTL defaults to 12 hours and is configured with `OPENSMART_SESSION_TTL_HOURS`.

## CSRF

Authenticated mutating requests require an `X-CSRF-Token` header. The frontend obtains this token from `GET /api/auth/me` and stores it in memory for API calls.

## Login Lockout

Failed login attempts are tracked by username and client IP in the `login_attempts` table.

Configurable settings:

- `failed_login_limit`
- `lockout_minutes`

## Shell Execution

Backend shell hooks are run through `subprocess.run([...], shell=False)`. Do not change this to shell string execution. Keep shell scripts thin and validate inputs before using them.

Container provisioning (`app/provisioning.py`) follows the same rule: it shells out to `docker compose -f <path> up -d`/`down` as an argument array, never a shell string, and `<path>` is only ever built from a fixed allowlist of container names that actually exist under `opensmart/containers/run/` — request bodies can't inject an arbitrary path.

## Container Provisioning

The app can start/stop/restart the sibling tool containers (Suricata, Zeek, Arkime, OpenSearch, WireGuard, OpenVPN, Wazuh) that back enabled modules/tools, without the app container ever mounting `docker.sock` directly:

- A `docker-socket-proxy` sidecar container holds the real socket (mounted read-only into *that* container only) and exposes a filtered HTTP API. The app talks to it via `DOCKER_HOST`.
- The proxy's allowlist is explicit and narrow: `CONTAINERS`, `NETWORKS`, `IMAGES`, `VOLUMES`, `POST`. Everything else is off, including `EXEC` (no shelling into other running containers), `BUILD`, `SWARM`, `SECRETS`, and `SYSTEM`.
- Every provisioning request is admin-only, CSRF-protected, and audit-logged.
- See `docs/technical-overview.md` for a diagram of the full request path and a fuller discussion of the threat model (what this design does and doesn't protect against).

The VPN module (`app/vpn.py`) extends the same model: instance and user names are validated against strict patterns (`^[a-z0-9][a-z0-9-]{0,29}$` / `^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$`) before ever reaching a path or a command, key/cert crypto runs in one-off containers through the same proxy (EXEC stays blocked), and every mutation is admin-only, CSRF-protected and audit-logged (`vpn_instance_*`, `vpn_user_*`). Two deliberate tradeoffs to know about: OpenVPN PKI directories are made world-readable-within-the-mount (`chmod -R a+rwX`) because the one-off containers' root maps to a different host UID than the backend (the host path above the mount stays root-only), and WireGuard's `wg0.conf` — which embeds the server private key — is mode 0644 for the same reason. Client configs contain private keys; the download endpoint requires admin + CSRF and each download is audited.

## Embedded Tool URLs

Tool URLs are configured by admins and loaded into iframes only after a user clicks a tool card. Only configure trusted internal URLs. Browser framing can fail if the target tool sends restrictive `X-Frame-Options` or `Content-Security-Policy` headers.

The tools front-door proxy (`opensmart/containers/run/nginx/`, see `docs/architecture.md`) deliberately strips `X-Frame-Options` and `Content-Security-Policy` from the proxied tool responses so those UIs can embed in the OpenSMART iframe. That removes the tools' own clickjacking protection for the proxied path — acceptable here because the proxy serves them same-origin behind OpenSMART's own authenticated console, but it is a conscious trade-off: only expose the proxy port to trusted networks, and prefer direct url:port mode (new-tab, headers intact) for tools reached over untrusted paths. The proxy talks to the Wazuh/Proxmox/OPNsense HTTPS upstreams with certificate verification disabled (internal, self-signed) — a same-network integration convenience, not a substitute for real TLS trust to those hosts.

## Audit Visibility

Audit entries are stored in SQLite. Normal users can view their own logon events. Admin users can view the last 100 relevant logons and configuration/user changes.

Users can terminate all other active sessions from the Account page. The current session is preserved and the action is audited.

## Current Limitations

- Cookies are configured with `SameSite=Lax`; production deployments behind HTTPS should also use `Secure` cookies.
- `X-Forwarded-For` is trusted if present; production deployments should only trust this header from known reverse proxies.
- There are no automated security tests yet.
- Admin configuration currently accepts module config as a raw JSON string but does not validate JSON content.
- Uploaded logos are stored as data URLs in SQLite; keep image sizes modest.
- The `docker-socket-proxy` allowlist still grants `POST` on `CONTAINERS`/`IMAGES`/`NETWORKS`/`VOLUMES` — broader than a single "start/stop these exact containers" permission would ideally be. A compromised backend process could still create/remove containers and pull arbitrary images through the proxy, though it cannot `exec` into other containers, build images, touch Swarm, or reach host-level Docker state.
- Container provisioning has not yet been tested with concurrent/overlapping start-stop requests; the underlying `docker compose` calls are not currently serialized per-container.
