from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


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
