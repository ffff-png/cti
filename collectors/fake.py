import random
from typing import Iterator

from core.collector import Collector, HealthState, HealthStatus, RawRecord
from core.schema import SourceType

# Plages réservées à la documentation (RFC 5737) : aucune adresse réelle
DOC_PREFIXES = ["203.0.113", "198.51.100", "192.0.2"]
DOC_DOMAINS = ["malware-demo.example", "phish-demo.example", "c2-demo.test"]


class FakeCollector(Collector):
    source_id = "fake"
    source_type = SourceType.API

    def configure(self, config: dict) -> None:
        super().configure(config)
        self.count = config.get("count", 10)
        self.dup_every = config.get("dup_every", 4)   # 1 doublon toutes les N lignes
        self._rng = random.Random(config.get("seed", 42))
        self._stopped = False
        self._emitted = 0

    def _fake_content(self) -> str:
        if self._rng.random() < 0.5:
            ip = f"{self._rng.choice(DOC_PREFIXES)}.{self._rng.randint(1, 254)}"
            return f"Adresse IP suspecte observée : {ip}"
        dom = self._rng.choice(DOC_DOMAINS)
        return f"Domaine lié à une campagne de test : {dom}"

    def collect(self) -> Iterator[RawRecord]:
        previous = None
        for i in range(1, self.count + 1):
            if self._stopped:
                break
            if previous and i % self.dup_every == 0:
                content = previous            # doublon volontaire
            else:
                content = self._fake_content()
            previous = content
            self._emitted += 1
            yield RawRecord(
                source_id=self.source_id,
                source_type=self.source_type,
                content=content,
                metadata={"seq": i},
            )

    def health(self) -> HealthStatus:
        if self._stopped:
            return HealthStatus(HealthState.DOWN, "arrêté")
        return HealthStatus(HealthState.OK, f"{self._emitted} enregistrements émis")

    def stop(self) -> None:
        self._stopped = True

