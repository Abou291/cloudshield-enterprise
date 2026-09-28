from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import Connection, Engine, func, select
from sqlalchemy.orm import Session

from app.db.models import Base, SchemaMigrationRecord

CURRENT_SCHEMA_VERSION = 1
_POSTGRES_MIGRATION_LOCK_ID = 731015127


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[Connection], None]


def _baseline_schema(connection: Connection) -> None:
    """Create the current additive schema without adopting unowned legacy rows."""
    Base.metadata.create_all(bind=connection)


MIGRATIONS = (
    Migration(1, "baseline-tenant-schema", _baseline_schema),
)


def migrate_database(engine: Engine) -> int:
    """Apply known migrations once and fail closed on an unknown future schema."""
    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            connection.exec_driver_sql(
                f"SELECT pg_advisory_xact_lock({_POSTGRES_MIGRATION_LOCK_ID})"
            )

        SchemaMigrationRecord.__table__.create(bind=connection, checkfirst=True)
        applied = set(
            connection.execute(select(SchemaMigrationRecord.version)).scalars().all()
        )
        future = sorted(version for version in applied if version > CURRENT_SCHEMA_VERSION)
        if future:
            raise RuntimeError(
                "Database schema is newer than this AegisShield build "
                f"(database={future[-1]}, supported={CURRENT_SCHEMA_VERSION})"
            )

        for migration in MIGRATIONS:
            if migration.version in applied:
                continue
            migration.apply(connection)
            connection.execute(
                SchemaMigrationRecord.__table__.insert().values(
                    version=migration.version,
                    name=migration.name,
                    applied_at=datetime.now(UTC),
                )
            )
            applied.add(migration.version)

        return max(applied, default=0)


def schema_version(db: Session) -> int:
    version = db.scalar(select(func.max(SchemaMigrationRecord.version)))
    return int(version or 0)


def schema_is_current(db: Session) -> bool:
    return schema_version(db) == CURRENT_SCHEMA_VERSION
