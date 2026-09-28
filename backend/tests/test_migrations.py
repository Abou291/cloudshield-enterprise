import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from app.db.migrations import CURRENT_SCHEMA_VERSION, migrate_database, schema_version
from app.db.models import SchemaMigrationRecord


def test_fresh_database_is_migrated_and_idempotent() -> None:
    engine = create_engine("sqlite:///:memory:")

    assert migrate_database(engine) == CURRENT_SCHEMA_VERSION
    assert migrate_database(engine) == CURRENT_SCHEMA_VERSION

    with Session(engine) as db:
        assert schema_version(db) == CURRENT_SCHEMA_VERSION
        count = db.scalar(select(func.count()).select_from(SchemaMigrationRecord))
        assert count == 1


def test_migration_preserves_unowned_legacy_findings_table() -> None:
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE findings ("
                "fingerprint TEXT PRIMARY KEY, title TEXT NOT NULL"
                ")"
            )
        )
        connection.execute(
            text(
                "INSERT INTO findings (fingerprint, title) "
                "VALUES ('legacy-fingerprint', 'legacy finding')"
            )
        )

    migrate_database(engine)

    with engine.connect() as connection:
        row = connection.execute(
            text(
                "SELECT fingerprint, title FROM findings "
                "WHERE fingerprint='legacy-fingerprint'"
            )
        ).one()
        tables = {
            item[0]
            for item in connection.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
        }

    assert row == ("legacy-fingerprint", "legacy finding")
    assert "tenant_findings" in tables
    assert "schema_migrations" in tables


def test_newer_database_schema_fails_closed() -> None:
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        SchemaMigrationRecord.__table__.create(bind=connection)
        connection.execute(
            SchemaMigrationRecord.__table__.insert().values(
                version=CURRENT_SCHEMA_VERSION + 1,
                name="future-schema",
                applied_at="2026-09-28 08:00:00",
            )
        )

    with pytest.raises(RuntimeError, match="newer than this AegisShield build"):
        migrate_database(engine)
