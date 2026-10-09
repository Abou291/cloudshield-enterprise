"""Background monitor: ``python -m app.monitoring.worker`` runs a cycle per tenant forever."""

import logging
import signal
import time

from app.core.config import AwsConnection, get_settings
from app.db.session import SessionLocal, init_db
from app.monitoring.runtime import build_service
from app.services.desktop_connection import DesktopConnectionStore

log = logging.getLogger("aegisshield.monitor")


def tenant_connections() -> dict[str, AwsConnection]:
    settings = get_settings()
    connections = dict(settings.aws_connections)
    if settings.desktop_mode:
        local = DesktopConnectionStore(settings.desktop_config_path).get()
        if local is not None:
            connections.setdefault("demo", local)
    return connections


def run_once() -> None:
    settings = get_settings()
    for tenant_id, connection in tenant_connections().items():
        with SessionLocal() as db:
            try:
                result = build_service(db, tenant_id, connection, settings).run_cycle()
                log.info("tenant=%s %s", tenant_id, result)
            except Exception:  # noqa: BLE001 - one tenant must not stop the others
                db.rollback()
                log.exception("monitor cycle failed for tenant %s", tenant_id)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    settings = get_settings()
    init_db()
    stop = False

    def request_stop(*_: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    log.info("monitor started, interval=%ss", settings.monitor_interval_seconds)
    while not stop:
        run_once()
        deadline = time.monotonic() + settings.monitor_interval_seconds
        while not stop and time.monotonic() < deadline:
            time.sleep(1)


if __name__ == "__main__":
    main()
