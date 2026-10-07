from fastapi.testclient import TestClient

from app.core.domain import Finding, RiskBreakdown, Severity
from app.db.session import SessionLocal
from app.services.findings import FindingRepository


def sample(fingerprint: str) -> Finding:
    return Finding(
        fingerprint=fingerprint, source="aws", rule_id="TEST-001", title="Test",
        description="Test", severity=Severity.HIGH, resource_id="resource-1",
        resource_type="test", account_id="111111111111", region="eu-west-3",
        evidence={}, recommendation="Fix", risk=RiskBreakdown(score=70, reasons=[], factors={}),
    )


def test_summary_and_export_are_not_limited_to_the_first_500(client: TestClient) -> None:
    with SessionLocal() as db:
        repo = FindingRepository(db, "demo", "aws")
        repo.upsert_many([sample(f"{index:064x}") for index in range(603)])
        FindingRepository(db, "other", "aws").upsert_many([sample("a" * 64)])
        FindingRepository(db, "demo", "demo-fixture").upsert_many([sample("a" * 64)])
        db.commit()
    summary = client.get("/api/v1/posture-summary?source=aws").json()
    assert summary["active"] == 603
    assert summary["severities"]["high"] == 603
    assert summary["highest_risk"] == 70
    assert summary["latest_scan"] is None
    report = client.get("/api/v1/reports/security?source=aws").json()
    assert len(report["findings"]) == 603
    assert report["summary"]["findings"] == 603


def test_finding_detail_is_source_scoped_and_includes_closed(client: TestClient) -> None:
    scan = client.post("/api/v1/scans/demo").json()
    fp = scan["findings"][0]["fingerprint"]
    assert client.get(f"/api/v1/findings/{fp}?source=aws").status_code == 404
    client.patch(f"/api/v1/findings/{fp}/status", json={"status": "resolved"})
    closed = client.get(f"/api/v1/findings/{fp}?source=demo-fixture").json()
    assert closed["status"] == "resolved"
    summary = client.get("/api/v1/posture-summary?source=demo-fixture").json()
    assert summary["active"] == 6
    assert summary["states"]["resolved"] == 1
    assert summary["latest_scan"]["scan_id"] == scan["scan_id"]
