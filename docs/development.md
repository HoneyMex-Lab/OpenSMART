# Development

## Recommended Backend Workflow

Use `uv`:

```bash
cd opensmart
uv sync --project backend --python 3.13
uv run --project backend --python 3.13 uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

The backend supports Python `>=3.11,<3.14`. Python `3.13` is recommended; Python `3.14` is intentionally excluded until all native backend dependencies publish compatible wheels.

Or use the helper script:

```bash
./opensmart/scripts/dev_backend.sh
```

## Frontend Workflow

```bash
cd opensmart/frontend
npm install
npm run dev
```

Or use:

```bash
./opensmart/scripts/dev_frontend.sh
```

## Combined App Runner

```bash
./opensmart.sh start
```

`opensmart.sh` mirrors `opensmart/scripts/run_app.sh`'s own subcommands —
`start`, `stop`, `status`, `restart`, `reset-admin-password`,
`reset-data-all`, `reset-data-ids`, `reset-data-network`, `reset-all`,
`health` — forwarding to wherever the app actually runs (inside the
`opensmart` container if one exists, or directly on the host otherwise).
You can also call `run_app.sh` directly with the same subcommands:

```bash
./opensmart/scripts/run_app.sh --help
./opensmart/scripts/run_app.sh reset-admin-password
./opensmart/scripts/run_app.sh status
```

`run_app.sh start`/`restart` write `opensmart/logs/run_app.state` (PID,
bind host/port, prod mode) once the backend is confirmed alive, so a
separate later invocation of `status`/`stop`/`restart` can find and act on
the running instance.

## Verification Commands

Backend:

```bash
cd opensmart
uv run --project backend --python 3.13 python -m compileall backend/app
uv run --project backend --python 3.13 python -c "import backend.app.admin_tools; import backend.app.main; print('backend imports ok')"
```

Shell scripts:

```bash
bash -n opensmart.sh opensmart/scripts/run_app.sh opensmart/scripts/dev_backend.sh opensmart/scripts/dev_frontend.sh
```

Frontend, when Node.js/npm are installed:

```bash
cd opensmart/frontend
npm run build
```

## Adding Backend Routes

Add route modules under `opensmart/backend/app/routes/` and include them from `opensmart/backend/app/main.py`.

Use these dependency rules:

- Read-only authenticated routes can depend on `get_current_user`.
- Mutating authenticated routes should depend on `require_csrf`.
- Admin-only mutating routes should depend on `require_admin`.

## Adding Shell Hooks

Place scripts in `opensmart/backend/app/scripts/` and call them with `run_script()` from `opensmart/backend/app/shell.py`.

Rules:

- Keep scripts executable.
- Use `set -euo pipefail`.
- Validate inputs.
- Return machine-readable output where possible.
- Do not put secrets in command-line arguments or logs.

## Frontend Notes

- API calls are centralized in `opensmart/frontend/src/api.ts`.
- Shared types live in `opensmart/frontend/src/types.ts`.
- Admin-only navigation is filtered in `opensmart/frontend/src/components/Sidebar.tsx`.
- Responsive behavior is controlled in `opensmart/frontend/src/styles.css`.
- Static generated SVG assets live under `opensmart/frontend/public/assets/`.
- Tools iframe URLs and tool enablement/config are configured through `ToolsConfigPage.tsx`.
- OpenSMART module enablement/config is configured through `OpenSmartConfigPage.tsx`.
- Audit UI is implemented in `AuditPage.tsx` and backed by `/api/audit`.

## Dependency Notes

`opensmart/backend/requirements.txt` is maintained as a compatibility fallback, but `opensmart/backend/pyproject.toml` and `uv` are the default backend dependency source.

Frontend `package.json` currently uses `latest` dependency ranges. For reproducible frontend installs, run `npm install` and commit the generated lockfile.
