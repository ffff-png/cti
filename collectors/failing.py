from typing import Iterator

from core.collector import Collector, HealthState, HealthStatus, RawRecord
from core.schema import SourceType


class FailingCollector(Collector):
    """Collecteur de test : échoue toujours, pour valider le disjoncteur."""
    source_id = "failing"
    source_type = SourceType.SITE

    def collect(self) -> Iterator[RawRecord]:
        raise ConnectionError("source injoignable (échec simulé)")
        yield  # fait de cette méthode un générateur

    def health(self) -> HealthStatus:
        return HealthStatus(HealthState.DOWN, "échec simulé")
