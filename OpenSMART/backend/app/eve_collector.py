"""
Standalone EVE JSON collector daemon.

Continuously tails eve.json and indexes events into the telemetry databases,
handling Suricata log rotation safely via inode comparison and draining the
old file descriptor before switching to the new file.

Run:
  uv run --project backend --python 3.13 python -m backend.app.eve_collector \\
      --eve-path /var/log/suricata/eve.json

Environment variable overrides: EVE_PATH, EVE_POLL_INTERVAL, EVE_BATCH_SIZE.
"""

import argparse
import json
import logging
import os
import signal
import time
from pathlib import Path
from typing import Any

from .database import get_network_ids_db, get_network_traffic_db, now_iso
from .eve_ingest import (
    _update_state,
    compute_event_hash,
    normalize_network_event,
    shared_config,
    write_network_events,
)
from .network_ids import normalize_alert, write_alerts

logger = logging.getLogger(__name__)


class EveCollector:
    def __init__(self, args: argparse.Namespace) -> None:
        self.eve_path = Path(args.eve_path)
        self.poll_interval: float = args.poll_interval
        self.batch_size: int = args.batch_size
        self._stop = False
        self._fd: Any = None      # open TextIOWrapper
        self._fd_inode: int = 0   # st_ino of the open fd

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)
        logger.info("eve collector starting: path=%s poll_interval=%s batch_size=%s",
                    self.eve_path, self.poll_interval, self.batch_size)
        while not self._stop:
            try:
                self._tick()
            except Exception:
                logger.exception("collector tick error")
                time.sleep(self.poll_interval)
        if self._fd is not None:
            self._fd.close()
            self._fd = None
        logger.info("eve collector stopped")

    def _handle_signal(self, sig: int, _frame: Any) -> None:
        logger.info("received signal %d, stopping", sig)
        self._stop = True

    def _tick(self) -> None:
        if self._fd is None:
            if not self.eve_path.exists():
                time.sleep(self.poll_interval)
                return
            self._open()

        # Compare open fd inode vs current path inode to detect rotation.
        try:
            current_inode = os.stat(self.eve_path).st_ino
        except FileNotFoundError:
            # File gone mid-rotation — keep draining old fd until EOF.
            current_inode = 0

        rotated = current_inode != 0 and current_inode != self._fd_inode

        config = shared_config()
        alert_batch: list[dict[str, Any]] = []
        network_batch: list[dict[str, Any]] = []
        lines_in_batch = 0

        while True:
            line = self._fd.readline()
            if not line:
                break
            line = line.rstrip("\n")
            if not line:
                continue
            self._parse_line(line, alert_batch, network_batch, config)
            lines_in_batch += 1
            if len(alert_batch) + len(network_batch) >= self.batch_size:
                self._flush(alert_batch, network_batch)
                alert_batch.clear()
                network_batch.clear()
                # Save offset only after the batch has committed.
                self._save_offset(self._fd.tell())

        if alert_batch or network_batch:
            self._flush(alert_batch, network_batch)
            self._save_offset(self._fd.tell())
        elif lines_in_batch > 0:
            self._save_offset(self._fd.tell())

        if rotated:
            # Old fd has been drained to EOF; now switch to the new file.
            logger.info("rotation detected: old_inode=%d new_inode=%d, switching",
                        self._fd_inode, current_inode)
            self._fd.close()
            self._fd = None
            self._fd_inode = 0
            self._open()
        else:
            time.sleep(self.poll_interval)

    def _open(self) -> None:
        stat = os.stat(self.eve_path)
        saved_offset, saved_inode = self._load_state()

        if saved_inode != 0 and saved_inode != stat.st_ino:
            # Inode differs from last run: rotation happened between sessions.
            logger.info("inode changed since last run saved_inode=%d current_inode=%d, starting from 0",
                        saved_inode, stat.st_ino)
            saved_offset = 0
        elif saved_offset > stat.st_size:
            # File was truncated (copytruncate). Offset reset to avoid seeking past EOF.
            # copytruncate can lose events written after the copy but before truncation.
            logger.warning("truncation detected: saved_offset=%d file_size=%d, resetting to 0",
                           saved_offset, stat.st_size)
            saved_offset = 0

        self._fd = open(self.eve_path, "r", encoding="utf-8", errors="replace")  # noqa: SIM115
        self._fd_inode = stat.st_ino
        if saved_offset > 0:
            self._fd.seek(saved_offset)
        # Persist the inode so the next session can detect inter-run rotation.
        self._save_offset(saved_offset, inode=stat.st_ino)
        logger.info("opened eve.json inode=%d offset=%d", stat.st_ino, saved_offset)

    def _parse_line(
        self,
        line: str,
        alert_batch: list[dict[str, Any]],
        network_batch: list[dict[str, Any]],
        config: dict[str, Any],
    ) -> None:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("malformed JSON line (skipped): %.120s", line)
            return

        event_type = str(event.get("event_type", ""))

        if event_type == "alert":
            record = normalize_alert(
                event,
                keep_empty=config.get("keep_empty_alerts", False),
                index_pp=config.get("index_payload_printable", True),
            )
            if record:
                alert_batch.append(record)
        elif event_type:
            # Index all non-alert event types without protocol filtering;
            # the API layer filters by event_type on read.
            network_batch.append(normalize_network_event(event))

    def _flush(
        self,
        alert_batch: list[dict[str, Any]],
        network_batch: list[dict[str, Any]],
    ) -> None:
        if alert_batch:
            write_alerts(str(self.eve_path), alert_batch)
        if network_batch:
            write_network_events(str(self.eve_path), network_batch)

    def _load_state(self) -> tuple[int, int]:
        """Return (byte_offset, file_inode) from the most relevant ingest_state table."""
        for db_factory, table in (
            (get_network_ids_db, "network_ids_ingest_state"),
            (get_network_traffic_db, "network_traffic_ingest_state"),
        ):
            try:
                with db_factory() as db:
                    row = db.execute(
                        f"SELECT byte_offset, file_inode FROM {table} WHERE eve_json_path = ?",
                        (str(self.eve_path),),
                    ).fetchone()
                if row:
                    return int(row["byte_offset"]), int(row["file_inode"])
            except Exception:
                logger.debug("could not read state from %s", table)
        return 0, 0

    def _save_offset(self, offset: int, inode: int | None = None) -> None:
        if inode is not None:
            sql_tail = "byte_offset = ?, file_inode = ?"
            params: tuple[Any, ...] = (offset, inode)
        else:
            sql_tail = "byte_offset = ?"
            params = (offset,)
        for db_factory, table in (
            (get_network_ids_db, "network_ids_ingest_state"),
            (get_network_traffic_db, "network_traffic_ingest_state"),
        ):
            try:
                _update_state(db_factory, table, str(self.eve_path), sql_tail, params)
            except Exception:
                logger.warning("could not save offset to %s", table)


def main() -> None:
    parser = argparse.ArgumentParser(description="OpenSMART EVE JSON collector daemon")
    parser.add_argument(
        "--eve-path",
        default=os.environ.get("EVE_PATH", "/var/log/suricata/eve.json"),
        help="Path to eve.json (env: EVE_PATH)",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=float(os.environ.get("EVE_POLL_INTERVAL", "0.5")),
        help="Seconds to sleep when no new data is available (env: EVE_POLL_INTERVAL)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=int(os.environ.get("EVE_BATCH_SIZE", "500")),
        help="Events to buffer before flushing to SQLite (env: EVE_BATCH_SIZE)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    EveCollector(args).run()


if __name__ == "__main__":
    main()
