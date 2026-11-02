import ipaddress
import os
import re
import time
from typing import Iterator

import requests

from core.collector import Collector, HealthState, HealthStatus, RawRecord
from core.schema import SourceType
from core.state import StateStore

DOMAIN_OK = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")
URL_OK = re.compile(r"^https?://[^\s'\"<>]+$", re.I)
HEX = re.compile(r"^[a-f0-9]+$")
HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}

# type MISP -> (nature de chaque partie de la valeur, séparées par « | »)
TYPE_MAP = {
    "ip-src": ["ip"], "ip-dst": ["ip"],
    "ip-src|port": ["ip", "port"], "ip-dst|port": ["ip", "port"],
    "domain": ["domain"], "hostname": ["domain"], "domain|ip": ["domain", "ip"],
    "url": ["url"],
    "md5": ["md5"], "sha1": ["sha1"], "sha256": ["sha256"],
    "filename|md5": ["skip", "md5"], "filename|sha1": ["skip", "sha1"],
    "filename|sha256": ["skip", "sha256"],
}


class MISPCollector(Collector):
    """MISP (API REST officielle) : attributs d'une instance MISP (la vôtre ou celle d'un partenaire).
    Clé d'API dans la variable d'environnement MISP_API_KEY."""

    source_id = "misp"
    source_type = SourceType.API
    version = "0.1.0"

    def configure(self, config: dict) -> None:
        super().configure(config)
        self.base = config["base_url"].rstrip("/")
        self.key_env = config.get("api_key_env", "MISP_API_KEY")
        self.types = list(config.get("types", TYPE_MAP))
        self.to_ids_only = bool(config.get("to_ids_only", True))          # seulement les attributs « IDS »
        self.enforce_warninglist = bool(config.get("enforce_warninglist", True))   # retire les valeurs bénignes connues
        self.published_only = bool(config.get("published_only", True))
        self.tags = config.get("tags")                                     # ex. ["tlp:white"]
        self.limit = int(config.get("limit", 1000))
        self.max_pages = int(config.get("max_pages", 10))
        self.initial_days = float(config.get("initial_days", 7))
        self.timeout = int(config.get("timeout", 60))
        self.verify = config.get("ca_bundle") or bool(config.get("verify_tls", True))
        self._store = StateStore(self.source_id)                           # curseur sur disque
        saved = self._store.load().get("since")
        self._since = int(saved) if saved else None
        self._stopped = self._failed = False
        self._emitted = self._skipped = 0

    # ------------------------------------------------------------ valeurs
    @staticmethod
    def _clean(kind: str, text: str):
        text = text.strip()
        if kind == "ip":
            try:
                return str(ipaddress.ip_address(text))
            except ValueError:
                return None
        if kind == "domain":
            text = text.lower()
            return text if DOMAIN_OK.match(text) else None
        if kind == "url":
            return text if URL_OK.match(text) else None
        if kind in HASH_LEN:
            text = text.lower()
            return text if len(text) == HASH_LEN[kind] and HEX.match(text) else None
        return None

    def _indicators(self, attr: dict):
        """Liste de (valeur, nature, port) pour un attribut MISP (une valeur composée peut en donner deux)."""
        layout = TYPE_MAP.get(attr.get("type", ""))
        if not layout:
            return []
        parts = str(attr.get("value", "")).split("|")
        if len(parts) != len(layout):
            return [(None, None, None)]
        port = parts[layout.index("port")] if "port" in layout else None
        out = []
        for kind, part in zip(layout, parts):
            if kind in ("skip", "port"):
                continue
            out.append((self._clean(kind, part), kind, port))
        return out

    # ------------------------------------------------------------ collecte
    def collect(self) -> Iterator[RawRecord]:
        self._failed = False
        self._emitted = self._skipped = 0
        key = os.environ.get(self.key_env, "").strip()
        if not key:
            self._failed = True
            raise RuntimeError(f"clé d'API absente : définir {self.key_env} dans .env")
        since = self._since or int(time.time() - self.initial_days * 86400)
        headers = {"Authorization": key, "Accept": "application/json",
                   "Content-Type": "application/json", "User-Agent": "cti-collector-pfe/0.1"}
        newest = since
        try:
            for page in range(1, self.max_pages + 1):
                body = {"returnFormat": "json", "type": {"OR": self.types}, "timestamp": since,
                        "limit": self.limit, "page": page, "includeEventUuid": 1,
                        "enforceWarninglist": int(self.enforce_warninglist)}
                if self.to_ids_only:
                    body["to_ids"] = 1
                if self.published_only:
                    body["published"] = 1
                if self.tags:
                    body["tags"] = self.tags
                resp = requests.post(f"{self.base}/attributes/restSearch", json=body, headers=headers,
                                     timeout=self.timeout, verify=self.verify)
                resp.raise_for_status()
                inner = resp.json().get("response")
                attrs = inner.get("Attribute", []) if isinstance(inner, dict) else []
                for attr in attrs:
                    if self._stopped:
                        return
                    ts = int(attr.get("timestamp") or 0)
                    newest = max(newest, ts)
                    for value, kind, port in self._indicators(attr):
                        if not value:
                            self._skipped += 1
                            continue
                        self._emitted += 1
                        yield RawRecord(
                            source_id=self.source_id, source_type=self.source_type, content=value,
                            metadata={"misp_attribute_id": attr.get("id"), "misp_type": attr.get("type"),
                                      "category": attr.get("category"), "port": port,
                                      "event_id": attr.get("event_id"), "event_uuid": attr.get("event_uuid"),
                                      "comment": attr.get("comment"), "to_ids": attr.get("to_ids"),
                                      "attribute_timestamp": attr.get("timestamp"),
                                      "origin": self.base})
                if len(attrs) < self.limit:
                    break
        except Exception:
            self._failed = True
            raise
        if newest > (self._since or 0):                        # le curseur n'avance qu'après un succès complet
            self._since = newest
            self._store.save({"since": newest})

    def health(self) -> HealthStatus:
        if self._failed:
            return HealthStatus(HealthState.DOWN, "instance MISP inaccessible ou clé refusée")
        if self._skipped:
            return HealthStatus(HealthState.DEGRADED,
                                f"{self._emitted} émis, {self._skipped} ignorés (valeur invalide)")
        return HealthStatus(HealthState.OK, f"{self._emitted} indicateurs émis")

    def stop(self) -> None:
        self._stopped = True
