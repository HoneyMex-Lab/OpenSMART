# Development

## Recommended Backend Workflow

Use `uv`:

```bash
cd OpenSMART
uv sync --project backend --python 3.13
uv run --project backend --python 3.13 uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

The backend supports Python `>=3.11,<3.14`. Python `3.13` is recommended; Python `3.14` is intentionally excluded until all native backend dependencies publish compatible wheels.

Or use the helper script:

```bash
./OpenSMART/scripts/dev_backend.sh
```

## Frontend Workflow

```bash
cd OpenSMART/frontend
npm install
npm run dev
```

Or use:

```bash
./OpenSMART/scripts/dev_frontend.sh
```

## Combined App Runner

```bash
./opensmart.sh start --bind 0.0.0.0:8000
```

This wraps `OpenSMART/scripts/run_app.sh`, which can also be called directly.
Options (on `run_app.sh` — not exposed through `opensmart.sh` yet):

```bash
./OpenSMART/scripts/run_app.sh --help
./OpenSMART/scripts/run_app.sh --reset-admin-password
```

## Verification Commands

Backend:

```bash
cd OpenSMART
uv run --project backend --python 3.13 python -m compileall backend/app
uv run --project backend --python 3.13 python -c "import backend.app.admin_tools; import backend.app.main; print('backend imports ok')"
```

Shell scripts:

```bash
bash -n opensmart.sh OpenSMART/scripts/run_app.sh OpenSMART/scripts/dev_backend.sh OpenSMART/scripts/dev_frontend.sh
```

Frontend, when Node.js/npm are installed:

```bash
cd OpenSMART/frontend
npm run build
```

## Adding Backend Routes

Add route modules under `OpenSMART/backend/app/routes/` and include them from `OpenSMART/backend/app/main.py`.

Use these dependency rules:

- Read-only authenticated routes can depend on `get_current_user`.
- Mutating authenticated routes should depend on `require_csrf`.
- Admin-only mutating routes should depend on `require_admin`.

## Adding Shell Hooks

Place scripts in `OpenSMART/backend/app/scripts/` and call them with `run_script()` from `OpenSMART/backend/app/shell.py`.

Rules:

- Keep scripts executable.
- Use `set -euo pipefail`.
- Validate inputs.
- Return machine-readable output where possible.
- Do not put secrets in command-line arguments or logs.

## Frontend Notes

- API calls are centralized in `OpenSMART/frontend/src/api.ts`.
- Shared types live in `OpenSMART/frontend/src/types.ts`.
- Admin-only navigation is filtered in `OpenSMART/frontend/src/components/Sidebar.tsx`.
- Responsive behavior is controlled in `OpenSMART/frontend/src/styles.css`.
- Static generated SVG assets live under `OpenSMART/frontend/public/assets/`.
- Tools iframe URLs and tool enablement/config are configured through `ToolsConfigPage.tsx`.
- OpenSMART module enablement/config is configured through `OpenSmartConfigPage.tsx`.
- Audit UI is implemented in `AuditPage.tsx` and backed by `/api/audit`.

## Dependency Notes

`OpenSMART/backend/requirements.txt` is maintained as a compatibility fallback, but `OpenSMART/backend/pyproject.toml` and `uv` are the default backend dependency source.

Frontend `package.json` currently uses `latest` dependency ranges. For reproducible frontend installs, run `npm install` and commit the generated lockfile.
