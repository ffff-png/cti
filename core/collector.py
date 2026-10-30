from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Iterator
from uuid import uuid4

from core.schema import SourceType


class HealthState(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    DOWN = "down"


@dataclass
class HealthStatus:
    state: HealthState
    detail: str = ""


@dataclass
class RawRecord:
    source_id: str
    source_type: SourceType
    content: str                      # texte brut collecté
    metadata: dict = field(default_factory=dict)
    record_id: str = field(default_factory=lambda: str(uuid4()))
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "source_id": self.source_id,
            "source_type": self.source_type.value,
            "content": self.content,
            "metadata": self.metadata,
            "collected_at": self.collected_at,
        }


class Collector(ABC):
    source_id: str
    source_type: SourceType
    version: str = "0.1.0"

    def configure(self, config: dict) -> None:
        self.config = config

    @abstractmethod
    def collect(self) -> Iterator[RawRecord]:
        """Produit les enregistrements bruts, un par un."""

    @abstractmethod
    def health(self) -> HealthStatus:
        """État courant du collecteur."""

    def stop(self) -> None:
        """Arrêt propre (à surcharger si besoin)."""
