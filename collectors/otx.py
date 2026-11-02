import ipaddress
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Iterator

import requests

from core.collector import Collector, HealthState, HealthStatus, RawRecord
from core.schema import SourceType
from core.state import StateStore

API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
DOMAIN_OK = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
HASH_LEN = {"FileHash-MD5": 32, "FileHash-SHA1": 40, "FileHash-SHA256": 64}
HEX = re.compile(r"^[a-f0-9]+$")
SUPPORTED = {"IPv4", "IPv6", "domain", "hostname", "URL", *HASH_LEN}   # types gérés par le normalisateur


class OTXCollector(Collector):
    """AlienVault OTX (API officielle) : indicateurs des « pulses » auxquels le
    compte est abonné. Clé d'API dans la variable d'environnement OTX_API_KEY."""

    source_id = "otx"
    source_type = SourceType.API
    version = "0.1.0"

    def configure(self, config: dict) -> None:
        super().configure(config)
        self.url = config.get("url", API_URL)
        self.timeout = int(config.get("timeout", 30))
        self.page_size = int(config.get("page_size", 50))
        self.max_pages = int(config.get("max_pages", 5))
        self.initial_days = float(config.get("initial_days", 7))
        self.key_env = config.get("api_key_env", "OTX_API_KEY")
        # l'orchestrateur recrée le collecteur à chaque collecte : le curseur est sur disque
        self._store = StateStore(self.source_id)
        saved = self._store.load().get("since")
        self._since: datetime | None = datetime.fromisoformat(saved) if saved else None
        self._stopped = False
        self._failed = False
        self._emitted = 0
        self._skipped = 0

    def _get(self, url: str, params: dict | None, key: str) -> dict:
        resp = requests.get(
            url, params=params, timeout=self.timeout,
            headers={"X-OTX-API-KEY": key, "User-Agent": "cti-collector-pfe/0.1"},
        )
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _clean(indicator: str, itype: str) -> str | None:
        raw_value = indicator.strip()
        indicator = raw_value if itype == "URL" else raw_value.lower()
        try:
            if itype in ("IPv4", "IPv6"):
                return str(ipaddress.ip_address(indicator))
        except ValueError:
            return None
        if itype in HASH_LEN:
            return indicator if len(indicator) == HASH_LEN[itype] and HEX.match(indicator) else None
        if itype == "URL":
            return indicator if re.match(r"^https?://[^\s'\"<>]+$", indicator) else None
        return indicator if DOMAIN_OK.match(indicator) else None

    def collect(self) -> Iterator[RawRecord]:
        self._failed = False
        self._emitted = self._skipped = 0
        key = os.environ.get(self.key_env, "").strip()
        if not key:
            self._failed = True
            raise RuntimeError(f"clé d'API absente : définir {self.key_env} dans .env")

        started = datetime.now(timezone.utc)
        since = self._since or (started - timedelta(days=self.initial_days))
        url, params = self.url, {"limit": self.page_size,
                                 "modified_since": since.strftime("%Y-%m-%dT%H:%M:%S")}
        try:
            for _ in range(self.max_pages):
                data = self._get(url, params, key)
                for pulse in data.get("results", []):
                    yield from self._records(pulse)
                    if self._stopped:
                        return
                url, params = data.get("next"), None      # l'URL « next » contient déjà les filtres
                if not url:
                    break
        except Exception:
            self._failed = True
            raise
        self._since = started                              # avancer le curseur seulement en cas de succès
        self._store.save({"since": started.isoformat()})

    def _records(self, pulse: dict) -> Iterator[RawRecord]:
        meta_pulse = {
            "pulse_id": pulse.get("id"),
            "pulse_name": pulse.get("name"),
            "tags": pulse.get("tags", []),
            "adversary": pulse.get("adversary"),
            "malware_families": [m.get("display_name") for m in pulse.get("malware_families", [])
                                 if isinstance(m, dict)],
            "attack_ids": [a.get("id") for a in pulse.get("attack_ids", []) if isinstance(a, dict)],
            "targeted_countries": pulse.get("targeted_countries", []),
            "pulse_modified": pulse.get("modified"),
            "origin": "otx.alienvault.com",
        }
        for ind in pulse.get("indicators", []):
            itype = ind.get("type")
            value = self._clean(str(ind.get("indicator", "")), itype) if itype in SUPPORTED else None
            if not value:
                self._skipped += 1            # type non géré (URL, hash...) ou valeur invalide
                continue
            self._emitted += 1
            # content = uniquement l'indicateur : le normalisateur l'extrait sans ambiguïté
            yield RawRecord(
                source_id=self.source_id, source_type=self.source_type, content=value,
                metadata={**meta_pulse, "indicator_type": itype,
                          "indicator_created": ind.get("created")},
            )

    def health(self) -> HealthStatus:
        if self._failed:
            return HealthStatus(HealthState.DOWN, "API OTX inaccessible ou clé invalide")
        if self._skipped:
            return HealthStatus(HealthState.DEGRADED,
                                f"{self._emitted} émis, {self._skipped} indicateurs ignorés (type non géré ou invalide)")
        return HealthStatus(HealthState.OK, f"{self._emitted} indicateurs émis")

    def stop(self) -> None:
        self._stopped = True
