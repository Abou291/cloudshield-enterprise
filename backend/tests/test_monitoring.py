import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.monitoring.detectors import run_detectors
from app.monitoring.events import normalize_cloudtrail_event
from app.monitoring.notify import build_payload, send_webhook, validate_webhook_url
from app.monitoring.sources import (
    fetch_cloudtrail_events,
    fetch_guardduty_alerts,
    guardduty_severity,
    monitored_regions,
)

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def ct_item(
    event_id: str,
    name: str,
    *,
    minutes: int = 0,
    identity: dict | None = None,
    ip: str = "198.51.100.7",
    response: dict | None = None,
    additional: dict | None = None,
    params: dict | None = None,
    error: str | None = None,
) -> dict:
    record = {
        "eventID": event_id,
        "eventName": name,
        "eventSource": "iam.amazonaws.com",
        "eventTime": (T0 + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z"),
        "awsRegion": "us-east-1",
        "sourceIPAddress": ip,
        "userIdentity": identity or {"type": "IAMUser", "userName": "alice"},
        "responseElements": response,
        "additionalEventData": additional,
        "requestParameters": params,
    }
    if error:
        record["errorCode"] = error
    return {"EventId": event_id, "CloudTrailEvent": json.dumps(record)}


def events_of(*items: dict) -> list:
    return [e for e in (normalize_cloudtrail_event(i) for i in items) if e]


def rule_ids(events: list, baseline: dict | None = None) -> set[str]:
    alerts, _ = run_detectors(events, baseline)
    return {a.rule_id for a in alerts}


def test_normalize_skips_malformed_records() -> None:
    assert normalize_cloudtrail_event({"CloudTrailEvent": "not json"}) is None
    assert normalize_cloudtrail_event({"CloudTrailEvent": "{}"}) is None
    event = normalize_cloudtrail_event(ct_item("e1", "ListBuckets"))
    assert event is not None and event.principal_name == "alice"


def test_root_login_is_critical() -> None:
    item = ct_item(
        "r1",
        "ConsoleLogin",
        identity={"type": "Root", "arn": "arn:aws:iam::1:root"},
        response={"ConsoleLogin": "Success"},
    )
    alerts, _ = run_detectors(events_of(item))
    assert any(a.rule_id == "DET-001" and a.severity == "critical" for a in alerts)


def test_login_without_mfa_flagged_but_with_mfa_not() -> None:
    no_mfa = ct_item(
        "l1", "ConsoleLogin", response={"ConsoleLogin": "Success"}, additional={"MFAUsed": "No"}
    )
    with_mfa = ct_item(
        "l2", "ConsoleLogin", response={"ConsoleLogin": "Success"}, additional={"MFAUsed": "Yes"}
    )
    assert "DET-002" in rule_ids(events_of(no_mfa))
    assert "DET-002" not in rule_ids(events_of(with_mfa))


def test_failed_login_burst_needs_threshold() -> None:
    fails = [
        ct_item(f"f{i}", "ConsoleLogin", minutes=i, response={"ConsoleLogin": "Failure"})
        for i in range(5)
    ]
    assert "DET-003" in rule_ids(events_of(*fails))
    assert "DET-003" not in rule_ids(events_of(*fails[:3]))


def test_security_tampering_and_persistence() -> None:
    stop = ct_item("t1", "StopLogging", params={"name": "main"})
    key = ct_item("p1", "CreateAccessKey", params={"userName": "bob"})
    ids = rule_ids(events_of(stop, key))
    assert "DET-004" in ids


def test_failed_calls_do_not_trigger_tampering() -> None:
    stop = ct_item("t2", "StopLogging", error="AccessDenied")
    assert "DET-004" not in rule_ids(events_of(stop))


def test_new_login_source_learns_then_alerts() -> None:
    first = ct_item("a1", "ConsoleLogin", response={"ConsoleLogin": "Success"}, ip="1.1.1.1")
    second = ct_item(
        "a2", "ConsoleLogin", minutes=5, response={"ConsoleLogin": "Success"}, ip="2.2.2.2"
    )
    alerts, learned = run_detectors(events_of(first), {})
    assert "DET-008" not in {a.rule_id for a in alerts}
    assert learned["alice"] == ["1.1.1.1"]
    alerts, learned = run_detectors(events_of(second), learned)
    assert "DET-008" in {a.rule_id for a in alerts}
    assert set(learned["alice"]) == {"1.1.1.1", "2.2.2.2"}


def test_alert_ids_are_stable_for_deduplication() -> None:
    item = ct_item("t9", "StopLogging")
    first, _ = run_detectors(events_of(item))
    again, _ = run_detectors(events_of(item))
    assert [a.alert_id for a in first] == [a.alert_id for a in again]


class FakeTrail:
    def __init__(self, pages: list[dict], fail: bool = False) -> None:
        self.pages = pages
        self.fail = fail
        self.calls = 0

    def lookup_events(self, **_: object) -> dict:
        if self.fail:
            raise RuntimeError("boom")
        page = self.pages[self.calls]
        self.calls += 1
        return page


def test_fetch_cloudtrail_paginates_dedupes_and_is_fail_soft() -> None:
    item = ct_item("x1", "StopLogging")
    trail = FakeTrail([{"Events": [item], "NextToken": "n"}, {"Events": [item]}])
    broken = FakeTrail([], fail=True)

    def client(service: str, region: str) -> FakeTrail:
        return broken if region == "us-east-1" else trail

    events, errors = fetch_cloudtrail_events(
        client, ["eu-west-3", "us-east-1"], T0, T0 + timedelta(hours=1), sleep=lambda _: None
    )
    assert len(events) == 1
    assert errors == ["cloudtrail:us-east-1:RuntimeError"]


def test_monitored_regions_include_global_event_region() -> None:
    assert monitored_regions("eu-west-3") == ["eu-west-3", "us-east-1"]
    assert monitored_regions("us-east-1") == ["us-east-1"]


def test_guardduty_findings_become_alerts() -> None:
    finding = {
        "Id": "f-1",
        "Title": "Crypto mining",
        "Type": "CryptoCurrency:EC2/BitcoinTool.B",
        "Severity": 8,
        "UpdatedAt": "2026-10-01T12:00:00Z",
        "Region": "eu-west-3",
        "Resource": {"ResourceType": "Instance"},
    }
    gd = SimpleNamespace(
        list_detectors=lambda: {"DetectorIds": ["d1"]},
        list_findings=lambda **_: {"FindingIds": ["f-1"]},
        get_findings=lambda **_: {"Findings": [finding]},
    )
    alerts, errors = fetch_guardduty_alerts(lambda s, r: gd, "eu-west-3", T0)
    assert errors == []
    assert alerts[0].severity == "high" and alerts[0].source == "guardduty"
    assert guardduty_severity(9) == "critical" and guardduty_severity(1) == "low"


def test_guardduty_denied_is_reported_not_raised() -> None:
    def client(service: str, region: str) -> object:
        raise RuntimeError("denied")

    alerts, errors = fetch_guardduty_alerts(client, "eu-west-3", T0)
    assert alerts == [] and errors == ["guardduty:eu-west-3:RuntimeError"]


def test_webhook_validation_and_failure_isolation() -> None:
    assert validate_webhook_url("https://hooks.example.com/x")
    assert validate_webhook_url("http://localhost:9000/x")
    for bad in ("http://example.com/x", "ftp://example.com", "https://"):
        try:
            validate_webhook_url(bad)
        except ValueError:
            continue
        raise AssertionError(bad)
    alerts, _ = run_detectors(events_of(ct_item("w1", "StopLogging")))
    sent: list[bytes] = []
    assert send_webhook("https://hooks.example.com/x", alerts, lambda u, b: sent.append(b))

    def failing(url: str, body: bytes) -> None:
        raise OSError("down")

    assert send_webhook("https://hooks.example.com/x", alerts, failing) is False
    assert "text" in build_payload(alerts) and sent


def test_service_cycle_dedupes_and_advances_cursor() -> None:
    from app.db.session import SessionLocal
    from app.monitoring.service import MonitorService

    items = [ct_item("s1", "StopLogging")]
    delivered: list[int] = []

    def fetch(start: datetime, end: datetime):
        return events_of(*items), []

    now = {"t": T0 + timedelta(hours=1)}
    with SessionLocal() as db:
        service = MonitorService(db, "t1", fetch, now=lambda: now["t"])
        first = service.run_cycle()
        now["t"] += timedelta(minutes=15)
        second = service.run_cycle()
        delivered.extend([first["alerts_new"], second["alerts_new"]])
    assert delivered == [1, 0]


def test_service_total_failure_keeps_cursor() -> None:
    from app.db.models import MonitorState
    from app.db.session import SessionLocal
    from app.monitoring.service import MonitorService

    with SessionLocal() as db:
        service = MonitorService(db, "t2", lambda s, e: ([], ["cloudtrail:x:Denied"]))
        result = service.run_cycle()
        state = db.get(MonitorState, "t2")
    assert result["status"] == "error" and state.cursor is None


def test_monitoring_endpoints_without_connection(client: TestClient) -> None:
    status = client.get("/api/v1/monitoring/status")
    assert status.status_code == 200
    assert status.json()["status"] == "never_run"
    assert client.get("/api/v1/monitoring/alerts").json() == []
    assert client.post("/api/v1/monitoring/run").status_code == 403
    assert client.post("/api/v1/monitoring/alerts/nope/ack").status_code == 404
