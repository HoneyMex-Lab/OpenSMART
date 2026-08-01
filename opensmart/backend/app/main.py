import asyncio
import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone

import anyio
import psutil
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import APP_VERSION, BUILD_VERSION, FRONTEND_DIST_DIR, FRONTEND_ORIGIN, resolve_log_path
from .database import get_db, init_db, init_network_ids_db, init_network_traffic_db
from . import retention as _retention
from .routes import account, audit, auth, firewall, modules, network_config, network_ids, network_ids_config, network_traffic, opensmart_modules, provisioning, settings, status, tools, users, vpn

app = FastAPI(title="OpenSMART API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup() -> None:
    init_db()
    init_network_ids_db()
    init_network_traffic_db()
    _configure_file_logging()
    await _configure_thread_limiter()
    _start_resource_sampler()
    _start_wazuh_autohealer()
    _start_network_mtu_reapply()
    asyncio.create_task(_retention_loop())


def _configure_file_logging() -> None:
    try:
        with get_db() as db:
            row = db.execute("SELECT value FROM settings WHERE key = 'log_file_path'").fetchone()
    except sqlite3.OperationalError:
        row = None
    log_file_path = row["value"] if row else None
    path = resolve_log_path(log_file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    root_logger = logging.getLogger()
    # Avoid adding duplicate handlers on reload
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == str(path) for h in root_logger.handlers):
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        root_logger.addHandler(handler)
        if root_logger.level == logging.NOTSET or root_logger.level > logging.INFO:
            root_logger.setLevel(logging.INFO)
        # Write an initial line so the log file is created immediately at startup.
        logging.getLogger(__name__).info("OpenSMART backend started: version=%s build=%s log=%s", APP_VERSION, BUILD_VERSION, path)


# Configure file logging at import time so the FileHandler is registered before
# uvicorn applies its own dictConfig (which would otherwise clobber our handler
# or change the root logger level). The startup() event also calls this function;
# the duplicate-handler guard makes it a no-op if already added, but it re-reads
# the DB for any user-configured log_file_path set after the first import.
_configure_file_logging()


async def _configure_thread_limiter() -> None:
    with get_db() as db:
        row = db.execute("SELECT value FROM settings WHERE key = 'worker_threads'").fetchone()
    worker_threads = int(row["value"]) if row and row["value"].isdigit() else 8
    limiter = anyio.to_thread.current_default_thread_limiter()
    limiter.total_tokens = max(4, worker_threads)


async def _retention_loop() -> None:
    from . import eve_ingest
    _log = logging.getLogger(__name__)
    while True:
        try:
            shared = eve_ingest.shared_config()
            times = []
            if shared.get("ids_retention_enabled"):
                times.append(str(shared.get("ids_retention_time", "02:00")))
            if shared.get("network_retention_enabled"):
                times.append(str(shared.get("network_retention_time", "02:00")))
            next_run_time = min(times) if times else "02:00"
            now = datetime.now(timezone.utc)
            try:
                h, m = (int(x) for x in next_run_time.split(":")[:2])
            except (ValueError, AttributeError):
                h, m = 2, 0
            target = now.replace(hour=h, minute=m, second=0, microsecond=0)
            if target <= now:
                target = target.replace(day=target.day + 1) if target.day < 28 else target.replace(
                    day=1, month=target.month + 1 if target.month < 12 else 1,
                    year=target.year if target.month < 12 else target.year + 1,
                )
            delay = (target - now).total_seconds()
            await asyncio.sleep(max(60, delay))
            await asyncio.to_thread(_retention.run_retention_job)
        except asyncio.CancelledError:
            break
        except Exception:
            _log.exception("retention loop error")
            await asyncio.sleep(3600)


def _start_resource_sampler() -> None:
    def _sample_loop() -> None:
        from datetime import timedelta
        while True:
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory().percent
                disk = psutil.disk_usage("/").percent
                now = datetime.now(timezone.utc).isoformat()
                prune_before = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
                with get_db() as db:
                    db.execute(
                        "INSERT INTO resource_snapshots (sampled_at, cpu_percent, memory_percent, disk_percent) VALUES (?, ?, ?, ?)",
                        (now, cpu, mem, disk),
                    )
                    db.execute("DELETE FROM resource_snapshots WHERE sampled_at < ?", (prune_before,))
                    db.commit()
            except Exception:
                pass
            time.sleep(60)

    t = threading.Thread(target=_sample_loop, daemon=True, name="resource-sampler")
    t.start()


def _start_wazuh_autohealer() -> None:
    """Continuously watch the Wazuh dashboard's HTTP health and auto-restart it
    out of the persistent-500 state it can get stuck in after a fresh install
    (see provisioning.wazuh_autoheal_tick). No-ops cheaply when Wazuh isn't
    provisioned. Runs in a daemon thread since the tick does blocking docker
    calls."""
    from . import provisioning

    def _heal_loop() -> None:
        _log = logging.getLogger(__name__)
        # Small initial delay so we don't probe during the backend's own boot.
        time.sleep(30)
        while True:
            try:
                provisioning.wazuh_autoheal_tick()
            except Exception:
                _log.exception("wazuh auto-heal tick error")
            time.sleep(45)

    t = threading.Thread(target=_heal_loop, daemon=True, name="wazuh-autohealer")
    t.start()


def _start_network_mtu_reapply() -> None:
    """One-shot: restore any admin-set interface MTU that doesn't survive a
    reboot/DHCP renewal (see network_config.reapply_mtus — MTU is fail-open by
    design, so this just re-establishes already-confirmed state, not a new
    risky change). Runs in a daemon thread since it does blocking docker
    calls; best-effort so a Docker hiccup at boot can't block API startup."""
    from . import network_config

    def _reapply() -> None:
        _log = logging.getLogger(__name__)
        try:
            network_config.reapply_mtus()
        except Exception:
            _log.exception("startup MTU re-apply error")

    threading.Thread(target=_reapply, daemon=True, name="network-mtu-reapply").start()


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.get("/api/health")
def health() -> JSONResponse:
    return JSONResponse({"ok": True})


app.include_router(auth.router)
app.include_router(account.router)
app.include_router(settings.router)
app.include_router(modules.router)
app.include_router(tools.router)
app.include_router(opensmart_modules.router)
app.include_router(network_ids.router)
app.include_router(network_ids_config.router)
app.include_router(network_config.router)
app.include_router(firewall.router)
app.include_router(network_traffic.router)
app.include_router(status.router)
app.include_router(users.router)
app.include_router(audit.router)
app.include_router(provisioning.router)
app.include_router(vpn.router)

# Serve the built frontend (opensmart/frontend/dist) if it exists — used in
# production/container mode where the app runs on a single port. Mounted
# last so it never shadows the API routes above (Starlette matches routes
# in registration order). In dev, dist/ is never built, so this is a no-op.
if (FRONTEND_DIST_DIR / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST_DIR), html=True), name="frontend")
