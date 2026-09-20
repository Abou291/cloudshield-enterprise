"""Local administration; never exposed as an HTTP endpoint."""

import argparse
import hashlib
import json
import secrets
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from app.db.models import AuditRecord, ScanLock, ScanRecord


def recover_scan(db: Session, tenant: str, scan_id: str) -> None:
    """Caller must stop ALL scanner processes first. Compare-and-delete guards stale input."""
    removed = db.execute(
        delete(ScanLock).where(
            ScanLock.tenant_id == tenant,
            ScanLock.scan_id == scan_id,
        )
    )
    if removed.rowcount != 1:
        db.rollback()
        raise ValueError("No matching scan lock; nothing changed")
    changed = db.execute(
        update(ScanRecord)
        .where(
            ScanRecord.tenant_id == tenant,
            ScanRecord.scan_id == scan_id,
            ScanRecord.status == "running",
        )
        .values(
            status="interrupted", error_code="OPERATOR_RECOVERY", completed_at=datetime.now(UTC)
        )
    )
    if changed.rowcount != 1:
        db.rollback()
        raise ValueError("No matching running scan; nothing changed")
    db.add(
        AuditRecord(
            event_id=str(uuid4()),
            tenant_id=tenant,
            subject="local-administrator",
            action="scan.interrupted",
            object_id=scan_id,
            timestamp=datetime.now(UTC),
        )
    )
    db.commit()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generate = commands.add_parser("generate-key")
    generate.add_argument("--tenant", required=True)
    generate.add_argument("--subject", required=True)
    generate.add_argument("--role", choices=["viewer", "operator"], default="viewer")
    recover = commands.add_parser("recover-scan")
    recover.add_argument("--tenant", required=True)
    recover.add_argument("--scan-id", required=True)
    recover.add_argument("--confirm-scanners-stopped", action="store_true", required=True)
    args = parser.parse_args()
    if args.command == "generate-key":
        from app.core.config import ApiPrincipal

        token = secrets.token_urlsafe(32)
        principal = ApiPrincipal(
            key_sha256=hashlib.sha256(token.encode()).hexdigest(),
            tenant_id=args.tenant,
            subject=args.subject,
            role=args.role,
        )
        print("Store this token securely; do not commit it:")
        print(token)
        print("Server configuration entry (hash only):")
        print(json.dumps(principal.model_dump()))
    else:
        from app.db.session import SessionLocal

        with SessionLocal() as db:
            recover_scan(db, args.tenant, args.scan_id)
        print("Scan marked interrupted; lock released. Previous findings preserved.")


if __name__ == "__main__":
    main()
