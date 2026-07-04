# Security Notes

This project includes basic local security controls suitable for a prototype. Review and harden before production use.

## Passwords

- Password hashes use Argon2 through `argon2-cffi`.
- Plaintext passwords are never stored in SQLite.
- First-run and reset passwords are printed once to the terminal.
- Reset passwords are not written to logs.

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

## Embedded Tool URLs

Tool URLs are configured by admins and loaded into iframes only after a user clicks a tool card. Only configure trusted internal URLs. Browser framing can fail if the target tool sends restrictive `X-Frame-Options` or `Content-Security-Policy` headers.

## Audit Visibility

Audit entries are stored in SQLite. Normal users can view their own logon events. Admin users can view the last 100 relevant logons and configuration/user changes.

Users can terminate all other active sessions from the Account page. The current session is preserved and the action is audited.

## Current Limitations

- Cookies are configured with `SameSite=Lax`; production deployments behind HTTPS should also use `Secure` cookies.
- `X-Forwarded-For` is trusted if present; production deployments should only trust this header from known reverse proxies.
- There is no password complexity policy beyond minimum length.
- There are no automated security tests yet.
- Admin configuration currently accepts module config as a raw JSON string but does not validate JSON content.
- Uploaded logos are stored as data URLs in SQLite; keep image sizes modest.
