# Architecture

OpenSMART is split into a Python backend, a React frontend, and Bash operational hooks.

## Runtime Components

- Frontend: React + TypeScript + Vite, served by the Vite dev server during development.
- Backend: FastAPI application with SQLite persistence.
- Database: local SQLite file, defaulting to `backend/opensmart.db`.
- Shell hooks: Bash scripts under `backend/app/scripts/`, executed by Python with `subprocess.run([...], shell=False)`.

## Request Flow

1. Browser loads the React app from `http://localhost:5173`.
2. Vite proxies `/api` requests to `http://localhost:8000`.
3. FastAPI routes authenticate requests through session cookies.
4. Mutating routes require an `X-CSRF-Token` header matching the CSRF cookie/session value.
5. SQLite stores users, sessions, settings, module configuration, and failed-login counters.

## Backend Layout

- `backend/app/main.py`: FastAPI app, middleware, startup initialization, router registration.
- `backend/app/config.py`: environment-driven paths and app settings.
- `backend/app/database.py`: SQLite schema, seed data, first-run admin bootstrap.
- `backend/app/security.py`: password hashing, sessions, CSRF, login lockout, auth dependencies.
- `backend/app/admin_tools.py`: admin password reset utility and admin action logging.
- `backend/app/shell.py`: safe shell hook execution wrapper.
- `backend/app/routes/`: API route modules.
- `backend/app/scripts/`: Bash hooks used by backend routes.

## Frontend Layout

- `frontend/src/App.tsx`: auth bootstrap and app-level state.
- `frontend/src/api.ts`: fetch wrapper and API client functions.
- `frontend/src/components/`: login, shell, and sidebar components.
- `frontend/src/pages/`: OpenSMART modules, tools, account, status, audit, about, WebConsole Config, Tools Config, OpenSMART Config, wizard, and access pages.
- `frontend/public/assets/`: local generated SVG assets for tool and summary cards.
- `frontend/src/styles.css`: responsive dark theme and layout styles.

## Admin Bootstrap

On backend startup, `init_db()` creates the schema and default records. If no admin user exists, it creates username `admin` with a generated password and prints it once.

`scripts/run_app.sh` watches backend startup output for the first-run marker and pauses so the operator can save the password before the frontend starts.

## Placeholder Integrations

The current tool integrations are placeholders. `GET /api/status` calls `backend/app/scripts/module_status.sh`, which returns demo JSON. Tool entries use admin-configured internal URLs and load iframe content only after a tool is selected. Future production integrations should keep shell scripts thin and move complex logic into Python modules.
