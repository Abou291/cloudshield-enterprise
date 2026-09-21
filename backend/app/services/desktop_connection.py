"""Local-only AWS connection configuration for the packaged desktop application."""

from pathlib import Path

from app.core.config import AwsConnection


class DesktopConnectionStore:
    """Persists role metadata only; AWS credentials are never written to disk."""

    def __init__(self, path: Path | None) -> None:
        self.path = path

    def get(self) -> AwsConnection | None:
        if self.path is None or not self.path.exists():
            return None
        return AwsConnection.model_validate_json(self.path.read_text(encoding="utf-8"))

    def save(self, connection: AwsConnection) -> None:
        if self.path is None:
            raise RuntimeError("Desktop configuration path is not available")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(connection.model_dump_json(), encoding="utf-8")
        temporary.replace(self.path)
