"""Webhook delivery of new alerts (Slack/Teams/Discord-compatible JSON, plain HTTPS)."""

import json
import urllib.request
from collections.abc import Callable
from urllib.parse import urlparse

from app.monitoring.events import SEVERITY_ORDER, Alert

Poster = Callable[[str, bytes], None]
LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def validate_webhook_url(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("Webhook URL must include a host")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and host in LOOPBACK):
        raise ValueError("Webhook URL must use HTTPS")
    return url


def build_payload(alerts: list[Alert]) -> dict:
    ordered = sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 0), reverse=True)
    lines = [f"AegisShield: {len(ordered)} new security alert(s)"]
    for alert in ordered[:10]:
        lines.append(f"[{alert.severity.upper()}] {alert.rule_id} {alert.title} - {alert.summary}")
    if len(ordered) > 10:
        lines.append(f"... and {len(ordered) - 10} more")
    return {
        "text": "\n".join(lines),
        "alerts": [
            {
                "id": a.alert_id,
                "rule_id": a.rule_id,
                "severity": a.severity,
                "title": a.title,
                "principal": a.principal,
                "source_ip": a.source_ip,
                "occurred_at": a.occurred_at.isoformat(),
            }
            for a in ordered
        ],
    }


def _post(url: str, body: bytes) -> None:
    request = urllib.request.Request(  # noqa: S310 - scheme validated above
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=10):  # noqa: S310
        pass


def send_webhook(url: str, alerts: list[Alert], post: Poster = _post) -> bool:
    """Deliver alerts; return False (never raise) when delivery fails."""
    if not alerts:
        return True
    try:
        post(validate_webhook_url(url), json.dumps(build_payload(alerts)).encode())
    except Exception:  # noqa: BLE001 - a broken webhook must not stop monitoring
        return False
    return True
