from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "instance": None}


def test_demo_scan_persists_and_deduplicates_findings(client: TestClient) -> None:
    first = client.post("/api/v1/scans/demo")
    second = client.post("/api/v1/scans/demo")
    findings = client.get("/api/v1/findings")

    assert first.status_code == 201
    assert first.json()["assets_scanned"] == 4
    assert first.json()["findings_count"] == 7
    assert second.status_code == 201
    assert len(findings.json()) == 7


def test_filter_findings_by_severity(client: TestClient) -> None:
    client.post("/api/v1/scans/demo")

    response = client.get("/api/v1/findings", params={"severity": "critical"})

    assert response.status_code == 200
    assert len(response.json()) == 2
    assert all(item["severity"] == "critical" for item in response.json())


def test_finding_lifecycle_api_and_resolved_history(client: TestClient) -> None:
    client.post("/api/v1/scans/demo")
    findings = client.get("/api/v1/findings").json()
    fingerprint = findings[0]["fingerprint"]

    acknowledged = client.patch(
        f"/api/v1/findings/{fingerprint}/status",
        json={"status": "acknowledged"},
    )
    assert acknowledged.status_code == 200
    assert acknowledged.json()["status"] == "acknowledged"

    resolved = client.patch(
        f"/api/v1/findings/{fingerprint}/status",
        json={"status": "resolved"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["status"] == "resolved"

    active = client.get("/api/v1/findings").json()
    assert all(item["fingerprint"] != fingerprint for item in active)

    history = client.get(
        "/api/v1/findings",
        params={"include_resolved": "true"},
    ).json()
    assert any(
        item["fingerprint"] == fingerprint and item["status"] == "resolved"
        for item in history
    )

    audit = client.get("/api/v1/audit").json()
    actions = {item["action"] for item in audit}
    assert "finding.acknowledged" in actions
    assert "finding.resolved" in actions



def test_risk_intelligence_endpoints_correlate_demo_findings(client: TestClient) -> None:
    client.post("/api/v1/scans/demo")

    summary = client.get(
        "/api/v1/executive-summary",
        params={"source": "demo-fixture"},
    )
    paths = client.get(
        "/api/v1/attack-paths",
        params={"source": "demo-fixture"},
    )

    assert summary.status_code == 200
    payload = summary.json()
    assert payload["findings"] == 7
    assert payload["critical"] == 2
    assert payload["internet_exposed"] >= 1
    assert payload["privileged"] >= 1
    assert payload["attack_path_candidates"] >= 2

    assert paths.status_code == 200
    path_payload = paths.json()
    assert len(path_payload) >= 2
    assert all(item["confidence"] == "candidate" for item in path_payload)
    assert all("does not prove" in item["caveat"] for item in path_payload)
    assert any(item["kind"] == "exposure-to-privilege" for item in path_payload)
