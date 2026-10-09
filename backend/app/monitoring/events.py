"""Normalised security events and alerts, independent of AWS client libraries."""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    name: str
    event_source: str
    time: datetime
    region: str
    principal_type: str
    principal_arn: str
    principal_name: str
    source_ip: str
    mfa_used: bool | None = None
    console_login: str | None = None  # "Success" | "Failure" for ConsoleLogin events
    error_code: str | None = None
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def principal_key(self) -> str:
        return self.principal_arn or self.principal_name or "unknown"


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    occurred_at: datetime
    principal: str
    source_ip: str
    region: str
    summary: str
    dedupe_key: str
    event_ids: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)
    source: str = "cloudtrail"

    @property
    def alert_id(self) -> str:
        return hashlib.sha256(f"{self.rule_id}|{self.dedupe_key}".encode()).hexdigest()


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _parse_time(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


def normalize_cloudtrail_event(item: dict[str, Any]) -> SecurityEvent | None:
    """Convert one ``LookupEvents`` item (with its embedded CloudTrail JSON) to an event.

    Returns None for records that cannot be interpreted; a monitor must never crash on
    one malformed event.
    """
    raw = item.get("CloudTrailEvent")
    try:
        record = json.loads(raw) if isinstance(raw, str) else _as_dict(raw)
    except ValueError:
        return None
    if not record:
        return None
    identity = _as_dict(record.get("userIdentity"))
    issuer = _as_dict(_as_dict(identity.get("sessionContext")).get("sessionIssuer"))
    name = identity.get("userName") or issuer.get("userName") or item.get("Username") or ""
    when = _parse_time(record.get("eventTime")) or _parse_time(item.get("EventTime"))
    event_id = record.get("eventID") or item.get("EventId")
    if when is None or not event_id:
        return None
    additional = _as_dict(record.get("additionalEventData"))
    mfa = additional.get("MFAUsed")
    response = _as_dict(record.get("responseElements"))
    login = response.get("ConsoleLogin")
    return SecurityEvent(
        event_id=str(event_id),
        name=str(record.get("eventName") or item.get("EventName") or ""),
        event_source=str(record.get("eventSource") or ""),
        time=when,
        region=str(record.get("awsRegion") or ""),
        principal_type=str(identity.get("type") or ""),
        principal_arn=str(identity.get("arn") or ""),
        principal_name=str(name),
        source_ip=str(record.get("sourceIPAddress") or ""),
        mfa_used=(mfa == "Yes") if mfa in {"Yes", "No"} else None,
        console_login=login if isinstance(login, str) else None,
        error_code=record.get("errorCode") if isinstance(record.get("errorCode"), str) else None,
        params=_as_dict(record.get("requestParameters")),
    )
