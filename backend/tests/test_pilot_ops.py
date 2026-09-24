import sqlite3

from app.services.backup import DesktopBackupService


def test_diagnostics_and_security_report(client):
    diagnostics = client.get("/api/v1/diagnostics")
    assert diagnostics.status_code == 200
    assert diagnostics.json()["backend"] == "ok"
    assert diagnostics.json()["database"] == "ok"

    client.post("/api/v1/scans/demo")
    report = client.get("/api/v1/reports/security?source=demo-fixture")
    assert report.status_code == 200
    body = report.json()
    assert body["schema"] == "aegisshield.security-report.v1"
    assert body["summary"]["findings"] == 7
    assert body["summary"]["highest_risk"] is not None
    assert len(body["integrity_sha256"]) == 64
    assert len(body["findings"]) == 7


def test_desktop_backup_and_restore_round_trip(tmp_path):
    database = tmp_path / "aegisshield.db"
    backup_dir = tmp_path / "backups"

    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sample (value TEXT NOT NULL)")
        connection.execute("INSERT INTO sample VALUES ('before')")
        connection.commit()

    service = DesktopBackupService(f"sqlite:///{database}", backup_dir)
    backup = service.create()
    assert backup["size_bytes"] > 0
    assert len(backup["sha256"]) == 64

    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE sample SET value = 'after'")
        connection.commit()

    service.restore_latest()
    with sqlite3.connect(database) as connection:
        value = connection.execute("SELECT value FROM sample").fetchone()[0]
    assert value == "before"
