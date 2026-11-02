import hashlib
import random
import re
import time
from typing import Iterator
from urllib.parse import urljoin, urlparse

import os
import requests
from bs4 import BeautifulSoup

from core.collector import Collector, HealthState, HealthStatus, RawRecord
from core.ioc import extract_iocs
from core.schema import SourceType
from core.state import StateStore
from core.tor import TorClient, TorError

ONION_V3 = re.compile(r"^[a-z2-7]{56}\.onion$")
ALLOWED_TYPES = {"text/html", "application/xhtml+xml", "text/plain", "application/json"}


class OnionCollector(Collector):
    """Collecte passive via Tor sur une LISTE BLANCHE d'adresses .onion validée par le promoteur.
    Texte seulement, aucune exploration de liens, aucune connexion à un compte ; le contenu des
    pages n'est pas conservé : seuls les indicateurs (IP, domaines, URL, hash) sont publiés."""

    source_id = "onion"
    source_type = SourceType.DARKWEB
    version = "0.1.0"

    def configure(self, config: dict) -> None:
        super().configure(config)
        raw_targets = config.get("targets") or []
        if not raw_targets:
            raise ValueError("aucune cible : la liste des adresses .onion doit être validée par le promoteur")
        self.targets = []
        for t in raw_targets:
            u = urlparse(str(t["url"]).strip())
            if u.scheme not in ("http", "https") or not ONION_V3.match(u.hostname or ""):
                raise ValueError(f"cible refusée (adresse .onion v3 attendue) : {t['url']}")
            self.targets.append({"url": u.geturl(), "host": u.hostname, "name": t.get("name", u.hostname)})
        self.allowed_hosts = {t["host"] for t in self.targets}
        self.tor = TorClient(
            socks=config.get("socks", "127.0.0.1:9050"),
            control=config.get("control", "127.0.0.1:9051"),
            control_password=os.environ.get(config.get("control_password_env", "TOR_CONTROL_PASSWORD")),
            check_url=config.get("check_url", "https://check.torproject.org/api/ip"),
            min_newnym_interval=float(config.get("min_newnym_interval", 10)))
        self.verify_tor = bool(config.get("verify_tor", True))
        self.rotate_every = max(1, int(config.get("rotate_every", 5)))
        lo, hi = config.get("delay", [8, 25])
        self.delay = (float(lo), float(hi))
        self.timeout = int(config.get("timeout", 60))
        self.max_bytes = int(config.get("max_bytes", 1_000_000))
        self.ignore_domains = {d.lower() for d in config.get("ignore_domains", [])}
        self._store = StateStore(self.source_id)
        self._hashes = dict(self._store.load().get("hashes", {}))
        self._stopped = self._failed = False
        self._emitted = self._pages = self._errors = self._blocked = self._unchanged = 0
        self._truncated = self._rotation_failures = 0

    # ------------------------------------------------------------ page
    def _fetch(self, session, url: str):
        """Texte de la page, ou None. Redirections : uniquement vers une adresse de la liste blanche."""
        for _ in range(3):
            try:
                resp = session.get(url, stream=True, allow_redirects=False, timeout=self.timeout)
            except requests.RequestException:
                self._errors += 1
                return None
            try:
                if 300 <= resp.status_code < 400:
                    url = urljoin(url, resp.headers.get("Location", ""))
                    if urlparse(url).hostname not in self.allowed_hosts:
                        self._blocked += 1
                        return None
                    continue
                if resp.status_code >= 400:
                    self._errors += 1
                    return None
                ctype = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
                if ctype not in ALLOWED_TYPES or "attachment" in resp.headers.get("Content-Disposition", "").lower():
                    self._blocked += 1                      # image, binaire, téléchargement : refusé
                    return None
                data, size = [], 0
                for chunk in resp.iter_content(65536):
                    size += len(chunk)
                    data.append(chunk)
                    if size > self.max_bytes:
                        self._truncated += 1
                        break
                body = b"".join(data)[: self.max_bytes].decode(resp.encoding or "utf-8", "replace")
                if ctype in ("text/html", "application/xhtml+xml"):
                    soup = BeautifulSoup(body, "html.parser")
                    for tag in soup(["script", "style", "noscript"]):
                        tag.decompose()
                    return soup.get_text(" ")
                return body
            finally:
                resp.close()
        self._blocked += 1
        return None

    # ------------------------------------------------------------ collecte
    def collect(self) -> Iterator[RawRecord]:
        self._failed = False
        try:
            self.tor.ensure_reachable()                      # sinon on s'arrête : jamais de connexion directe
            if self.verify_tor:                                          # identité jetable : le contrôle
                checker = self.tor.session()                             # ne partage aucun circuit avec la collecte
                self.tor.verify_exit(checker)
                checker.close()
            session = self.tor.session()
            order = random.sample(self.targets, len(self.targets))      # ordre aléatoire
            for n, target in enumerate(order):
                if self._stopped:
                    break
                if n:
                    if n % self.rotate_every == 0:                       # nouveaux circuits
                        try:
                            self.tor.new_identity()
                        except TorError:
                            self._rotation_failures += 1     # non fatal : la nouvelle identité SOCKS isole déjà
                        session.close()
                        session = self.tor.session()
                    time.sleep(random.uniform(*self.delay))              # rythme irrégulier
                text = self._fetch(session, target["url"])
                if text is None:
                    continue
                self._pages += 1
                digest = hashlib.sha256(text.encode()).hexdigest()
                if self._hashes.get(target["url"]) == digest:
                    self._unchanged += 1                                 # page inchangée : rien à extraire
                    continue
                for kind, value in extract_iocs(text, self.ignore_domains | {target["host"]}):
                    self._emitted += 1
                    yield RawRecord(                                     # le texte de la page n'est pas gardé
                        source_id=self.source_id, source_type=self.source_type, content=value,
                        metadata={"target": target["name"], "onion_host": target["host"],
                                  "indicator_kind": kind, "origin": "tor"})
                self._hashes[target["url"]] = digest
            if self._pages == 0 and not self._stopped:
                raise TorError("aucune cible .onion joignable")
        except Exception:
            self._failed = True
            raise
        finally:
            self._store.save({"hashes": self._hashes})

    def health(self) -> HealthStatus:
        if self._failed:
            return HealthStatus(HealthState.DOWN, "Tor injoignable ou aucune cible joignable")
        problems = self._errors + self._blocked + self._rotation_failures + self._truncated
        if problems:
            return HealthStatus(HealthState.DEGRADED,
                                f"{self._pages} pages, {self._errors} erreurs, {self._blocked} refusées, "
                                f"{self._truncated} tronquées, {self._rotation_failures} rotations échouées")
        return HealthStatus(HealthState.OK, f"{self._pages} pages, {self._emitted} indicateurs, "
                                            f"{self._unchanged} inchangées")

    def stop(self) -> None:
        self._stopped = True
