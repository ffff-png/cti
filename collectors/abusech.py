"""Collecteurs abuse.ch (API officielles, clé gratuite Auth-Key) : ThreatFox et URLhaus."""
import ipaddress
import math
import os
import re
from datetime import datetime, timezone
from typing import Iterator

import requests

from core.collector import Collector, HealthState, HealthStatus, RawRecord
from core.schema import SourceType
from core.state import StateStore

DOMAIN_OK = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
URL_OK = re.compile(r"^https?://[^\s'\"<>]+$", re.I)
HEX = re.compile(r"^[a-f0-9]+$")
UA = "cti-collector-pfe/0.1"


def parse_utc(text):
    """'2026-10-30 09:10:23 UTC' -> datetime UTC (None si illisible)."""
    try:
        return datetime.strptime(str(text).replace("UTC", "").strip(),
                                 "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class _AbuseCh(Collector):
    source_type = SourceType.API
    version = "0.1.0"

    def configure(self, config: dict) -> None:
        super().configure(config)
        self.timeout = int(config.get("timeout", 30))
        self.key_env = config.get("api_key_env", "ABUSECH_AUTH_KEY")
        # le collecteur est recréé à chaque collecte : le curseur vit sur disque
        self._store = StateStore(self.source_id)
        saved = self._store.load().get("since")
        self._since = datetime.fromisoformat(saved) if saved else None
        self._stopped = self._failed = False
        self._emitted = self._skipped = 0

    def _key(self) -> str:
        key = os.environ.get(self.key_env, "").strip()
        if not key:
            self._failed = True
            raise RuntimeError(f"clé d'API absente : définir {self.key_env} dans .env "
                               "(clé gratuite sur auth.abuse.ch)")
        return key

    def _is_new(self, when) -> bool:
        return not (when and self._since and when <= self._since)

    def _commit(self, newest) -> None:
        if newest and not self._stopped:               # le curseur n'avance qu'après un succès complet
            self._since = newest
            self._store.save({"since": newest.isoformat()})

    def health(self) -> HealthStatus:
        if self._failed:
            return HealthStatus(HealthState.DOWN, "API abuse.ch inaccessible ou clé invalide")
        if self._skipped:
            return HealthStatus(HealthState.DEGRADED,
                                f"{self._emitted} émis, {self._skipped} ignorés (type non géré ou invalide)")
        return HealthStatus(HealthState.OK, f"{self._emitted} indicateurs émis")

    def stop(self) -> None:
        self._stopped = True


class ThreatFoxCollector(_AbuseCh):
    """ThreatFox : IOC (IP:port, domaines, URL, hash) liés à des familles de malware."""
    source_id = "threatfox"

    def configure(self, config: dict) -> None:
        super().configure(config)
        self.url = config.get("url", "https://threatfox-api.abuse.ch/api/v1/")
        self.initial_days = min(7, max(1, int(config.get("initial_days", 1))))   # l'API plafonne à 7
        self.min_confidence = int(config.get("min_confidence", 0))

    @staticmethod
    def _value(item: dict):
        ioc, typ = str(item.get("ioc", "")).strip(), str(item.get("ioc_type", ""))
        if typ == "ip:port":                            # « 1.2.3.4:443 » : séparer l'IP du port
            host, _, port = ioc.rpartition(":")
            try:
                return str(ipaddress.ip_address(host)), port
            except ValueError:
                return None, None
        if typ == "domain":
            ioc = ioc.lower()
            return (ioc, None) if DOMAIN_OK.match(ioc) else (None, None)
        if typ == "url":
            return (ioc, None) if URL_OK.match(ioc) else (None, None)
        if typ.endswith("_hash"):
            ioc = ioc.lower()
            ok = len(ioc) in (32, 40, 64) and HEX.match(ioc)
            return (ioc, None) if ok else (None, None)
        return None, None

    def collect(self) -> Iterator[RawRecord]:
        self._failed = False
        self._emitted = self._skipped = 0
        key = self._key()
        if self._since:
            age = (datetime.now(timezone.utc) - self._since).total_seconds() / 86400
            days = min(7, max(1, math.ceil(age)))
        else:
            days = self.initial_days
        try:
            resp = requests.post(self.url, json={"query": "get_iocs", "days": days},
                                 headers={"Auth-Key": key, "User-Agent": UA}, timeout=self.timeout)
            resp.raise_for_status()
            body = resp.json()
            status = body.get("query_status")
            if status == "no_result":
                return
            if status != "ok":
                raise RuntimeError(f"ThreatFox a répondu : {status}")
            newest = None
            for item in body.get("data") or []:
                if self._stopped:
                    break
                seen = parse_utc(item.get("first_seen"))
                if not self._is_new(seen):
                    continue                            # déjà publié lors d'une collecte précédente
                if seen and (newest is None or seen > newest):
                    newest = seen
                value, port = self._value(item)
                try:
                    low_conf = int(item.get("confidence_level", 100)) < self.min_confidence
                except (TypeError, ValueError):
                    low_conf = False
                if not value or low_conf:
                    self._skipped += 1
                    continue
                self._emitted += 1
                yield RawRecord(
                    source_id=self.source_id, source_type=self.source_type, content=value,
                    metadata={"threatfox_id": item.get("id"),
                              "threatfox_url": f"https://threatfox.abuse.ch/ioc/{item.get('id')}/",
                              "ioc_type": item.get("ioc_type"), "port": port,
                              "threat_type": item.get("threat_type"),
                              "malware": item.get("malware_printable") or item.get("malware"),
                              "malware_alias": item.get("malware_alias"),
                              "confidence_level": item.get("confidence_level"),
                              "tags": item.get("tags") or [],
                              "first_seen": item.get("first_seen"),
                              "origin": "threatfox.abuse.ch"})
            self._commit(newest)
        except Exception:
            self._failed = True
            raise


class URLhausCollector(_AbuseCh):
    """URLhaus : URL de distribution de malware."""
    source_id = "urlhaus"

    def configure(self, config: dict) -> None:
        super().configure(config)
        self.base = config.get("base_url", "https://urlhaus-api.abuse.ch/v1")
        self.limit = min(1000, max(1, int(config.get("limit", 1000))))
        self.only_online = bool(config.get("only_online", False))

    def collect(self) -> Iterator[RawRecord]:
        self._failed = False
        self._emitted = self._skipped = 0
        key = self._key()
        try:
            resp = requests.get(f"{self.base}/urls/recent/limit/{self.limit}/",
                                headers={"Auth-Key": key, "User-Agent": UA}, timeout=self.timeout)
            resp.raise_for_status()
            body = resp.json()
            status = body.get("query_status")
            if status == "no_results":
                return
            if status != "ok":
                raise RuntimeError(f"URLhaus a répondu : {status}")
            newest = None
            for item in body.get("urls") or []:
                if self._stopped:
                    break
                added = parse_utc(item.get("date_added"))
                if not self._is_new(added):
                    continue
                if added and (newest is None or added > newest):
                    newest = added
                url = str(item.get("url", "")).strip()
                if not URL_OK.match(url) or (self.only_online and item.get("url_status") != "online"):
                    self._skipped += 1
                    continue
                self._emitted += 1
                yield RawRecord(
                    source_id=self.source_id, source_type=self.source_type, content=url,
                    metadata={"urlhaus_id": item.get("id"),
                              "urlhaus_url": item.get("urlhaus_reference"),
                              "url_status": item.get("url_status"), "threat": item.get("threat"),
                              "tags": item.get("tags") or [], "host": item.get("host"),
                              "date_added": item.get("date_added"), "origin": "urlhaus.abuse.ch"})
            self._commit(newest)
        except Exception:
            self._failed = True
            raise
