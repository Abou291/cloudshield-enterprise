"""One monitoring cycle: fetch events, detect, deduplicate, persist, notify."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AlertRecord, MonitorState
from app.monitoring.detectors import run_detectors
from app.monitoring.events import Alert, SecurityEvent
from app.monitoring.notify import send_webhook

# CloudTrail records can show up in LookupEvents ~15 minutes late, so each cycle re-reads
# an overlap window. Alert deduplication makes the overlap harmless.
OVERLAP = timedelta(minutes=30)
DEFAULT_LOOKBACK = timedelta(hours=1)
MAX_LOOKBACK = timedelta(days=7)

EventFetcher = Callable[[datetime, datetime], tuple[list[SecurityEvent], list[str]]]
AlertFetcher = Callable[[datetime], tuple[list[Alert], list[str]]]


class MonitorService:
    def __init__(
        self,
        db: Session,
        tenant_id: str,
        fetch_events: EventFetcher,
        fetch_alerts: AlertFetcher | None = None,
        webhook_url: str | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.db = db
        self.tenant_id = tenant_id
        self.fetch_events = fetch_events
        self.fetch_alerts = fetch_alerts
        self.webhook_url = webhook_url
        self.now = now

    def _state(self) -> MonitorState:
        state = self.db.get(MonitorState, self.tenant_id)
        if state is None:
            state = MonitorState(tenant_id=self.tenant_id, baseline={}, last_errors=[])
            self.db.add(state)
        return state

    def run_cycle(self, lookback: timedelta = DEFAULT_LOOKBACK) -> dict:
        state = self._state()
        end = self.now()
        start = state.cursor.replace(tzinfo=UTC) if state.cursor else end - lookback
        start = max(start - OVERLAP if state.cursor else start, end - MAX_LOOKBACK)

        events, errors = self.fetch_events(start, end)
        alerts, learned = run_detectors(events, dict(state.baseline or {}))
        if self.fetch_alerts is not None:
            extra, extra_errors = self.fetch_alerts(start)
            alerts.extend(extra)
            errors.extend(extra_errors)

        fresh = self._store_new(alerts, end)
        notified = True
        if fresh and self.webhook_url:
            notified = send_webhook(self.webhook_url, fresh)
            if notified:
                self._mark_notified(fresh)

        total_failure = bool(errors) and not events and not alerts
        state.baseline = learned
        state.last_run_at = end
        state.last_errors = errors[:20]
        state.events_seen = len(events)
        state.alerts_new = len(fresh)
        state.last_status = "error" if total_failure else ("partial" if errors else "ok")
        if not total_failure:
            state.cursor = end
        self.db.commit()
        return {
            "status": state.last_status,
            "events_seen": len(events),
            "alerts_new": len(fresh),
            "errors": errors,
            "webhook_delivered": notified if self.webhook_url and fresh else None,
        }

    def _store_new(self, alerts: list[Alert], seen_at: datetime) -> list[Alert]:
        unique = {a.alert_id: a for a in alerts}
        if not unique:
            return []
        existing = set(
            self.db.scalars(
                select(AlertRecord.alert_id).where(
                    AlertRecord.tenant_id == self.tenant_id,
                    AlertRecord.alert_id.in_(list(unique)),
                )
            )
        )
        fresh = [a for alert_id, a in unique.items() if alert_id not in existing]
        for alert in fresh:
            self.db.add(
                AlertRecord(
                    tenant_id=self.tenant_id,
                    alert_id=alert.alert_id,
                    rule_id=alert.rule_id,
                    title=alert.title,
                    severity=alert.severity,
                    source=alert.source,
                    occurred_at=alert.occurred_at,
                    principal=alert.principal[:512],
                    source_ip=alert.source_ip,
                    region=alert.region,
                    summary=alert.summary,
                    details=alert.details,
                    status="open",
                    notified=False,
                    first_seen_at=seen_at,
                )
            )
        return fresh

    def _mark_notified(self, alerts: list[Alert]) -> None:
        for alert in alerts:
            record = self.db.get(AlertRecord, (self.tenant_id, alert.alert_id))
            if record is not None:
                record.notified = True


def health(state: MonitorState | None, interval_seconds: int, now: datetime) -> dict:
    """Summarise monitor health; ``stale`` means the schedule has been missed."""
    if state is None or state.last_run_at is None:
        return {"status": "never_run", "last_run_at": None, "stale": True, "errors": []}
    last = state.last_run_at.replace(tzinfo=UTC)
    stale = now - last > timedelta(seconds=interval_seconds * 3)
    return {
        "status": "stale" if stale else state.last_status,
        "last_run_at": last.isoformat(),
        "stale": stale,
        "events_seen": state.events_seen,
        "alerts_new": state.alerts_new,
        "errors": list(state.last_errors or []),
    }
