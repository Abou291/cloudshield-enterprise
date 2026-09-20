from typing import Protocol

from app.core.domain import Asset


class InventoryProvider(Protocol):
    def collect(self) -> list[Asset]: ...

