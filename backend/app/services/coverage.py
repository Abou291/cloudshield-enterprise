from typing import Any

from app.core.domain import Finding, FindingStatus, ScanHistory


def _gap_service(finding: Finding) -> str:
    service = finding.evidence.get("service")
    if isinstance(service, str) and service:
        return service
    parts = finding.resource_id.split(":")
    return parts[1] if len(parts) >= 3 else "unknown"


def _gap_reason(finding: Finding) -> str:
    reason = finding.evidence.get("reason")
    return reason if isinstance(reason, str) and reason else "unknown"


def build_coverage_summary(
    findings: list[Finding],
    scans: list[ScanHistory],
    source: str,
) -> dict[str, Any]:
    """Summarize what the latest scan could actually observe.

    COMPLETE means no scanner/API coverage gap was observed in the latest
    successful scan. It does not mean every AWS service or security control is
    implemented by AegisShield.
    """
    latest = next((scan for scan in scans if scan.source == source), None)
    active_gaps = [
        finding
        for finding in findings
        if finding.status != FindingStatus.RESOLVED and finding.rule_id == "COV-001"
    ]
    gaps = [
        {
            "service": _gap_service(finding),
            "reason": _gap_reason(finding),
            "region": finding.region,
            "resource_id": finding.resource_id,
            "fingerprint": finding.fingerprint,
        }
        for finding in active_gaps
    ]

    if latest is None:
        state = "unknown"
        message = "No scan has completed for this data source."
    elif latest.status != "succeeded":
        state = "unknown"
        message = (
            "The latest scan did not succeed; displayed findings and coverage "
            "information may be stale."
        )
    elif gaps:
        state = "incomplete"
        message = (
            "The scan completed, but one or more AWS services could not be inspected."
        )
    else:
        state = "complete"
        message = "No scanner/API coverage gap was observed in the latest successful scan."

    return {
        "state": state,
        "message": message,
        "source": source,
        "latest_scan_id": latest.scan_id if latest else None,
        "latest_scan_status": latest.status if latest else None,
        "latest_scan_completed_at": (
            latest.completed_at.isoformat()
            if latest is not None and latest.completed_at is not None
            else None
        ),
        "gap_count": len(gaps),
        "services": sorted({gap["service"] for gap in gaps}),
        "regions": sorted({gap["region"] for gap in gaps}),
        "reasons": sorted({gap["reason"] for gap in gaps}),
        "gaps": gaps,
        "caveat": (
            "Coverage state describes scanner/API observability for implemented "
            "AegisShield collectors only; it is not a statement that all AWS "
            "services, attack paths, or compliance controls were assessed."
        ),
    }
