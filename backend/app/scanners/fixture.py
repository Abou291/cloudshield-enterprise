import json
from pathlib import Path

from app.core.domain import Asset


class FixtureInventoryProvider:
    def __init__(self, fixture_path: Path) -> None:
        self.fixture_path = fixture_path

    def collect(self) -> list[Asset]:
        payload = json.loads(self.fixture_path.read_text(encoding="utf-8"))
        return [Asset.model_validate(item) for item in payload]
