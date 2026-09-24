import hashlib
import json
from collections import Counter
from datetime import UTC, datetime

from app.core.domain import Finding, ScanHistory


def build_security_report(
    tenant_id: str,
    source: str,
    findings: list[Finding],
    scans: list[ScanHistory],
) -> dict:
    counts = Counter(str(item.severity) for item in findings)
    highest_risk = max((item.risk.score for item in findings), default=None)
    latest = next((scan for scan in scans if scan.source == source), None)
    payload = {
        "schema": "aegisshield.security-report.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": tenant_id,
        "source": source,
        "summary": {
            "findings": len(findings),
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "highest_risk": highest_risk,
            "latest_scan_status": latest.status if latest else None,
            "latest_scan_started_at": (
                latest.started_at.isoformat() if latest else None
            ),
        },
        "findings": [item.model_dump(mode="json") for item in findings],
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    payload["integrity_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload
