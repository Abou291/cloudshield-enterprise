"""Read-only collection of security events: CloudTrail LookupEvents and GuardDuty findings.

Both sources are fail-soft per region: one denied or throttled call is reported in the
returned ``errors`` list and never aborts the cycle. Callers pass a ``client`` factory so
the logic is testable with botocore Stubber and never touches the network by itself.
"""

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from app.monitoring.events import Alert, SecurityEvent, normalize_cloudtrail_event

MAX_EVENTS_PER_REGION = 2000
MAX_GUARDDUTY_FINDINGS = 50
# LookupEvents is limited to ~2 requests/second per account and region.
LOOKUP_PAUSE_SECONDS = 0.55
# IAM and console sign-in events are recorded in us-east-1 regardless of the home region.
GLOBAL_EVENT_REGION = "us-east-1"

ClientFactory = Callable[[str, str], Any]


def monitored_regions(home_region: str) -> list[str]:
    regions = [home_region]
    if GLOBAL_EVENT_REGION not in regions:
        regions.append(GLOBAL_EVENT_REGION)
    return regions


def fetch_cloudtrail_events(
    client: ClientFactory,
    regions: list[str],
    start: datetime,
    end: datetime,
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[list[SecurityEvent], list[str]]:
    events: dict[str, SecurityEvent] = {}
    errors: list[str] = []
    for region in regions:
        try:
            trail = client("cloudtrail", region)
            token: str | None = None
            seen = 0
            while seen < MAX_EVENTS_PER_REGION:
                params: dict[str, Any] = {"StartTime": start, "EndTime": end, "MaxResults": 50}
                if token:
                    params["NextToken"] = token
                page = trail.lookup_events(**params)
                for item in page.get("Events", []):
                    seen += 1
                    event = normalize_cloudtrail_event(item)
                    if event is not None:
                        events[event.event_id] = event
                token = page.get("NextToken")
                if not token:
                    break
                sleep(LOOKUP_PAUSE_SECONDS)
        except Exception as exc:  # noqa: BLE001 - fail-soft by design
            errors.append(f"cloudtrail:{region}:{_code(exc)}")
    return sorted(events.values(), key=lambda e: e.time), errors


def _code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", type(exc).__name__))
    return type(exc).__name__


def guardduty_severity(score: float) -> str:
    if score >= 8.9:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def finding_to_alert(finding: dict[str, Any]) -> Alert | None:
    finding_id = finding.get("Id")
    if not finding_id:
        return None
    when = _parse(finding.get("UpdatedAt")) or _parse(finding.get("CreatedAt"))
    if when is None:
        return None
    resource = finding.get("Resource") or {}
    action = (finding.get("Service") or {}).get("Action") or {}
    remote = (
        (action.get("NetworkConnectionAction") or {}).get("RemoteIpDetails")
        or (action.get("AwsApiCallAction") or {}).get("RemoteIpDetails")
        or {}
    )
    return Alert(
        rule_id="GD-FINDING",
        title=str(finding.get("Title") or finding.get("Type") or "GuardDuty finding"),
        severity=guardduty_severity(float(finding.get("Severity") or 0)),
        occurred_at=when,
        principal=str(resource.get("ResourceType") or ""),
        source_ip=str(remote.get("IpAddressV4") or ""),
        region=str(finding.get("Region") or ""),
        summary=str(finding.get("Description") or "")[:500],
        dedupe_key=str(finding_id),
        details={"type": finding.get("Type"), "guardduty_severity": finding.get("Severity")},
        source="guardduty",
    )


def _parse(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def fetch_guardduty_alerts(
    client: ClientFactory, region: str, since: datetime
) -> tuple[list[Alert], list[str]]:
    alerts: list[Alert] = []
    try:
        gd = client("guardduty", region)
        detectors = gd.list_detectors().get("DetectorIds", [])
        since_ms = int(since.timestamp() * 1000)
        for detector_id in detectors:
            ids = gd.list_findings(
                DetectorId=detector_id,
                FindingCriteria={"Criterion": {"updatedAt": {"GreaterThanOrEqual": since_ms}}},
                MaxResults=MAX_GUARDDUTY_FINDINGS,
            ).get("FindingIds", [])
            if not ids:
                continue
            found = gd.get_findings(DetectorId=detector_id, FindingIds=ids).get("Findings", [])
            for finding in found:
                alert = finding_to_alert(finding)
                if alert is not None:
                    alerts.append(alert)
    except Exception as exc:  # noqa: BLE001 - fail-soft by design
        return alerts, [f"guardduty:{region}:{_code(exc)}"]
    return alerts, []
