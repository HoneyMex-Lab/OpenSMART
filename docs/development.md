# Development

## Recommended Backend Workflow

Use `uv`:

```bash
uv sync --project backend --python 3.13
uv run --project backend --python 3.13 uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

The backend supports Python `>=3.11,<3.14`. Python `3.13` is recommended; Python `3.14` is intentionally excluded until all native backend dependencies publish compatible wheels.

Or use the helper script:

```bash
./scripts/dev_backend.sh
```

## Frontend Workflow

```bash
cd frontend
npm install
npm run dev
```

Or use:

```bash
./scripts/dev_frontend.sh
```

## Combined App Runner

```bash
./scripts/run_app.sh
```

Options:

```bash
./scripts/run_app.sh --help
./scripts/run_app.sh --reset-admin-password
```

## Verification Commands

Backend:

```bash
uv run --project backend --python 3.13 python -m compileall backend/app
uv run --project backend --python 3.13 python -c "import backend.app.admin_tools; import backend.app.main; print('backend imports ok')"
```

Shell scripts:

```bash
bash -n scripts/run_app.sh scripts/dev_backend.sh scripts/dev_frontend.sh
```

Frontend, when Node.js/npm are installed:

```bash
cd frontend
npm run build
```

## Adding Backend Routes

Add route modules under `backend/app/routes/` and include them from `backend/app/main.py`.

Use these dependency rules:

- Read-only authenticated routes can depend on `get_current_user`.
- Mutating authenticated routes should depend on `require_csrf`.
- Admin-only mutating routes should depend on `require_admin`.

## Adding Shell Hooks

Place scripts in `backend/app/scripts/` and call them with `run_script()` from `backend/app/shell.py`.

Rules:

- Keep scripts executable.
- Use `set -euo pipefail`.
- Validate inputs.
- Return machine-readable output where possible.
- Do not put secrets in command-line arguments or logs.

## Frontend Notes

- API calls are centralized in `frontend/src/api.ts`.
- Shared types live in `frontend/src/types.ts`.
- Admin-only navigation is filtered in `frontend/src/components/Sidebar.tsx`.
- Responsive behavior is controlled in `frontend/src/styles.css`.
- Static generated SVG assets live under `frontend/public/assets/`.
- Tools iframe URLs and tool enablement/config are configured through `ToolsConfigPage.tsx`.
- OpenSMART module enablement/config is configured through `OpenSmartConfigPage.tsx`.
- Audit UI is implemented in `AuditPage.tsx` and backed by `/api/audit`.

## Dependency Notes

`backend/requirements.txt` is maintained as a compatibility fallback, but `backend/pyproject.toml` and `uv` are the default backend dependency source.

Frontend `package.json` currently uses `latest` dependency ranges. For reproducible frontend installs, run `npm install` and commit the generated lockfile.
