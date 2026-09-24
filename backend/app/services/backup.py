import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path


class DesktopBackupService:
    def __init__(self, database_url: str, backup_dir: Path) -> None:
        if not database_url.startswith("sqlite:///") or database_url == "sqlite://":
            raise RuntimeError("Desktop backup currently requires a file-backed SQLite database")
        self.database_path = Path(database_url.removeprefix("sqlite:///"))
        self.backup_dir = backup_dir

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _integrity_check(path: Path) -> None:
        with sqlite3.connect(path) as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
        if result is None or result[0] != "ok":
            raise RuntimeError("SQLite integrity check failed")

    def create(self) -> dict:
        if not self.database_path.exists():
            raise RuntimeError("Desktop database does not exist")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        destination = self.backup_dir / f"aegisshield-{stamp}.db"
        with sqlite3.connect(self.database_path) as source, sqlite3.connect(destination) as target:
            source.backup(target)
        self._integrity_check(destination)
        return {
            "file_name": destination.name,
            "path": str(destination),
            "size_bytes": destination.stat().st_size,
            "sha256": self._sha256(destination),
        }

    def latest(self) -> Path | None:
        if not self.backup_dir.exists():
            return None
        backups = sorted(
            self.backup_dir.glob("aegisshield-*.db"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        return backups[0] if backups else None

    def restore_latest(self) -> dict:
        source_path = self.latest()
        if source_path is None:
            raise RuntimeError("No desktop backup is available")
        self._integrity_check(source_path)
        with sqlite3.connect(source_path) as source, sqlite3.connect(self.database_path) as target:
            source.backup(target)
        self._integrity_check(self.database_path)
        return {
            "file_name": source_path.name,
            "path": str(source_path),
            "size_bytes": source_path.stat().st_size,
            "sha256": self._sha256(source_path),
        }
