import hashlib
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from app.admin import recover_scan
from app.api import router
from app.core import auth
from app.core.config import Settings
from app.db.models import ScanLock, ScanRecord
from app.db.session import SessionLocal
from app.services.findings import FindingRepository


@pytest.fixture
def secured(monkeypatch):
    keys = [
        ("token-a", "alpha", "operator"),
        ("token-b", "beta", "operator"),
        ("token-reader", "alpha", "viewer"),
    ]
    settings = Settings(
        _env_file=None,
        demo_mode=False,
        api_keys=[
            {
                "key_sha256": hashlib.sha256(token.encode()).hexdigest(),
                "tenant_id": tenant,
                "subject": role,
                "role": role,
            }
            for token, tenant, role in keys
        ],
        aws_connections={
            "alpha": {
                "role_arn": "arn:aws:iam::111111111111:role/scanner",
                "external_id": "test-external-id-alpha",
                "account_id": "111111111111",
            }
        },
    )
    monkeypatch.setattr(auth, "get_settings", lambda: settings)
    monkeypatch.setattr(router, "get_settings", lambda: settings)
    return settings


def headers(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize("path", ["session", "findings", "scans", "scans/unknown", "audit"])
def test_private_reads_require_authentication(client, secured, path):
    assert client.get(f"/api/v1/{path}").status_code == 401
    assert client.get(f"/api/v1/{path}", headers=headers("wrong")).status_code == 401


@pytest.mark.parametrize("path", ["demo", "aws"])
def test_scan_roles_enforced(client, secured, path):
    assert client.post(f"/api/v1/scans/{path}").status_code == 401
    response = client.post(f"/api/v1/scans/{path}", headers=headers("token-reader"))
    assert response.status_code == 403


def test_cross_tenant_isolation_and_untrusted_tenant_parameter(client, secured):
    scan_a = client.post("/api/v1/scans/demo", headers=headers("token-a")).json()
    b = headers("token-b") | {"X-Tenant-ID": "alpha"}
    assert client.get("/api/v1/findings?tenant_id=alpha", headers=b).json() == []
    assert client.get("/api/v1/scans", headers=b).json() == []
    assert client.get("/api/v1/audit", headers=b).json() == []
    assert client.get(f"/api/v1/scans/{scan_a['scan_id']}", headers=b).status_code == 404
    assert client.post("/api/v1/scans/demo", headers=b).status_code == 201
    assert len(client.get("/api/v1/findings", headers=b).json()) == 7
    assert len(client.get("/api/v1/findings", headers=headers("token-reader")).json()) == 7
    assert len(client.get("/api/v1/scans", headers=headers("token-a")).json()) == 1


def test_readonly_session_and_no_connection_disclosure(client, secured):
    response = client.get("/api/v1/session", headers=headers("token-reader"))
    assert response.json()["role"] == "viewer"
    assert response.json()["tenant_id"] == "alpha"
    assert "external_id" not in response.text
    assert "key_sha256" not in response.text


def test_demo_cannot_reach_aws(client, monkeypatch):
    provider = Mock()
    monkeypatch.setattr(router, "AwsInventoryProvider", provider)
    assert client.post("/api/v1/scans/aws").status_code == 403
    provider.assert_not_called()


def test_unconfigured_tenant_cannot_reach_aws(client, secured, monkeypatch):
    provider = Mock()
    monkeypatch.setattr(router, "AwsInventoryProvider", provider)
    assert client.post("/api/v1/scans/aws", headers=headers("token-b")).status_code == 403
    provider.assert_not_called()


def test_aws_source_separation_and_bound_connection(client, secured, monkeypatch):
    provider = Mock(return_value=router.FixtureInventoryProvider(router.FIXTURE_PATH))
    monkeypatch.setattr(router, "AwsInventoryProvider", provider)
    h = headers("token-a")
    assert client.post("/api/v1/scans/aws", headers=h).status_code == 201
    provider.assert_called_once_with(
        "eu-west-3",
        "arn:aws:iam::111111111111:role/scanner",
        "test-external-id-alpha",
        "111111111111",
        None,
    )
    assert client.get("/api/v1/findings", headers=h).json() == []
    assert client.post("/api/v1/scans/demo", headers=h).status_code == 201
    aws = client.get("/api/v1/findings?source=aws", headers=h).json()
    demo = client.get("/api/v1/findings", headers=h).json()
    assert len(aws) == len(demo) == 7
    assert all(item["source"] == "aws" for item in aws)
    assert all(item["source"] == "demo-fixture" for item in demo)


def test_failed_scan_keeps_previous_results_and_sanitizes_error(client, monkeypatch):
    client.post("/api/v1/scans/demo")
    before = client.get("/api/v1/findings").json()
    monkeypatch.setattr(
        router,
        "FixtureInventoryProvider",
        Mock(side_effect=RuntimeError("upstream-secret-must-not-be-exposed")),
    )
    response = client.post("/api/v1/scans/demo")
    assert response.status_code == 503
    assert client.get("/api/v1/findings").json() == before
    history = client.get("/api/v1/scans").json()
    assert history[0]["status"] == "failed"
    assert history[0]["error_code"] == "SCAN_FAILED"
    assert history[0]["completed_at"] is not None
    detail = client.get(f"/api/v1/scans/{history[0]['scan_id']}")
    audit = client.get("/api/v1/audit")
    assert "upstream-secret" not in response.text + detail.text + audit.text
    assert audit.json()[0]["action"] == "scan.failed"
    with SessionLocal() as db:
        assert db.scalars(select(ScanLock)).all() == []


def test_partial_persistence_is_rolled_back(client, monkeypatch):
    original = FindingRepository.upsert_many

    def fail_after_flush(self, findings):
        original(self, findings)
        raise RuntimeError("write interrupted")

    monkeypatch.setattr(FindingRepository, "upsert_many", fail_after_flush)
    assert client.post("/api/v1/scans/demo").status_code == 503
    assert client.get("/api/v1/findings").json() == []
    assert client.get("/api/v1/scans").json()[0]["status"] == "failed"


def test_durable_scan_lock_blocks_same_tenant_only(client, secured):
    with SessionLocal() as db:
        db.add(ScanLock(tenant_id="alpha", scan_id="already-running"))
        db.commit()
    assert client.post("/api/v1/scans/demo", headers=headers("token-a")).status_code == 409
    assert client.post("/api/v1/scans/demo", headers=headers("token-b")).status_code == 201


def test_pagination_is_stable_and_validated(client):
    client.post("/api/v1/scans/demo")
    full = client.get("/api/v1/findings").json()
    first = client.get("/api/v1/findings?limit=3").json()
    second = client.get("/api/v1/findings?limit=4&offset=3").json()
    assert first + second == full
    assert client.get("/api/v1/findings?offset=-1").status_code == 422
    assert client.get("/api/v1/scans?limit=501").status_code == 422


@pytest.mark.parametrize(
    "settings",
    [
        {"env": "production"},
        {"demo_mode": False, "api_keys": []},
        {"cors_origins": ["*"]},
        {"env": "prod"},
    ],
)
def test_insecure_settings_fail_closed(settings):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **settings)


def test_security_headers(client):
    response = client.get("/api/v1/health")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert len(response.headers["x-request-id"]) == 36


def test_recovery_requires_exact_tenant_scan_and_keeps_findings(client):
    result = client.post("/api/v1/scans/demo").json()
    scan_id = result["scan_id"]
    with SessionLocal() as db:
        db.get(ScanRecord, scan_id).status = "running"
        db.add(ScanLock(tenant_id="demo", scan_id=scan_id))
        db.commit()
        with pytest.raises(ValueError):
            recover_scan(db, "other", scan_id)
        assert db.get(ScanLock, "demo") is not None
        recover_scan(db, "demo", scan_id)
        assert db.get(ScanLock, "demo") is None
    assert client.get(f"/api/v1/scans/{scan_id}").json()["status"] == "interrupted"
    assert len(client.get("/api/v1/findings").json()) == 7
    assert client.get("/api/v1/audit").json()[0]["action"] == "scan.interrupted"


def test_recovery_rolls_back_if_record_is_already_terminal(client):
    result = client.post("/api/v1/scans/demo").json()
    with SessionLocal() as db:
        db.add(ScanLock(tenant_id="demo", scan_id=result["scan_id"]))
        db.commit()
        with pytest.raises(ValueError, match="No matching running scan"):
            recover_scan(db, "demo", result["scan_id"])
        assert db.get(ScanLock, "demo") is not None
