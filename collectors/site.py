import os
import random
import time
import urllib.robotparser
from typing import Iterator
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from core.collector import Collector, HealthState, HealthStatus, RawRecord
from core.ioc import extract_iocs
from core.schema import SourceType
from core.state import StateStore

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class LoginError(RuntimeError):
    pass


class SiteCollector(Collector):
    """Collecteur générique de site spécialisé : session authentifiée (abonnement),
    lecture des articles, extraction des IOC. Tout se règle dans sources.yml."""

    source_id = "site"
    source_type = SourceType.SITE
    version = "0.1.0"

    # ------------------------------------------------------------ configuration
    def configure(self, config: dict) -> None:
        super().configure(config)
        self.base = config["base_url"].rstrip("/")
        self.host = urlparse(self.base).hostname
        self.list_url = config.get("list_url", "/")
        self.item_sel = config["item_selector"]
        self.content_sel = config["content_selector"]
        self.title_sel = config.get("title_selector")
        self.ioc_sel = config.get("ioc_selector")        # restreindre aux sections « IOC »
        self.next_sel = config.get("next_selector")
        self.max_pages = int(config.get("max_pages", 1))
        self.max_articles = int(config.get("max_articles", 30))
        lo, hi = config.get("delay", [1.0, 3.0])
        self.delay = (float(lo), float(hi))
        self.respect_robots = bool(config.get("respect_robots", True))
        self.timeout = int(config.get("timeout", 20))
        self.retries = int(config.get("retries", 3))
        self.backoff = float(config.get("backoff", 2.0))
        self.ua = config.get("user_agent", "Mozilla/5.0 (compatible; cti-collector-pfe/0.1)")
        self.ignore_domains = {d.lower() for d in config.get("ignore_domains", [])} | {self.host}
        self.auth = config.get("auth") or {}

        self._store = StateStore(self.source_id)
        state = self._store.load()
        self.seen: list[str] = list(state.get("seen", []))
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.ua, "Accept-Language": "fr,en;q=0.8"})
        for name, value in state.get("cookies", {}).items():
            self.session.cookies.set(name, value, domain=self.host)   # jamais envoyés à un autre hôte
        if self.auth.get("type") == "header":                         # jeton d'API / clé d'accès
            token = os.environ.get(self.auth["token_env"], "")
            if not token:
                raise LoginError(f"jeton absent : définir {self.auth['token_env']} dans .env")
            self.session.headers[self.auth.get("header_name", "Authorization")] = (
                self.auth.get("prefix", "Bearer ") + token)

        self._robots = None
        self._last_request = 0.0
        self._stopped = False
        self._failed = False
        self._emitted = self._articles = self._errors = self._blocked = self._logins = 0

    # ------------------------------------------------------------ réseau poli
    def _wait(self) -> None:
        if self._last_request:
            pause = random.uniform(*self.delay) - (time.time() - self._last_request)
            if pause > 0:
                time.sleep(pause)

    def _request(self, method: str, url: str, **kw) -> requests.Response:
        attempts = self.retries if method == "GET" else 1     # jamais de POST rejoué (verrouillage de compte)
        last_exc = None
        for n in range(attempts):
            self._wait()
            try:
                resp = self.session.request(method, url, timeout=self.timeout, **kw)
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                self._last_request = time.time()
                time.sleep(self.backoff * (2 ** n))
                continue
            self._last_request = time.time()
            if resp.status_code in (429, 502, 503, 504) and n < attempts - 1:
                try:
                    pause = min(float(resp.headers.get("Retry-After", "")), 30)
                except ValueError:
                    pause = self.backoff * (2 ** n)
                time.sleep(pause)
                continue
            return resp
        raise last_exc or requests.HTTPError(f"échec après {attempts} tentatives : {url}")

    def _allowed(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        if self._robots is None:
            self._robots = urllib.robotparser.RobotFileParser()
            try:
                r = self._request("GET", self.base + "/robots.txt")
                self._robots.parse(r.text.splitlines() if r.status_code == 200 else [])
            except Exception:
                self._robots.parse([])                         # robots.txt illisible : on autorise
        return self._robots.can_fetch(self.ua, url)

    # ------------------------------------------------------------ authentification
    def _logged_in(self, resp: requests.Response) -> bool:
        if not self.auth or self.auth.get("type") == "header":
            return resp.status_code not in (401, 403)
        if resp.status_code in (401, 403):
            return False
        soup = BeautifulSoup(resp.text, "html.parser")
        sel = self.auth.get("success_selector")
        return soup.select_one(sel) is not None if sel else soup.select_one("input[type=password]") is None

    def _login(self) -> None:
        a = self.auth
        user = os.environ.get(a.get("username_env", ""), "")
        pwd = os.environ.get(a.get("password_env", ""), "")
        if not user or not pwd:
            raise LoginError(f"identifiants absents : définir {a.get('username_env')} et "
                             f"{a.get('password_env')} dans .env")
        if self.base.startswith("http://") and self.host not in LOCAL_HOSTS:
            raise LoginError("refus d'envoyer des identifiants en clair (HTTP) : utiliser HTTPS")
        login_url = urljoin(self.base + "/", a.get("login_url", "/login").lstrip("/"))
        page = BeautifulSoup(self._request("GET", login_url).text, "html.parser")
        form = page.select_one(a.get("form_selector", "form"))
        data = {}
        if form:                                               # jetons CSRF et autres champs cachés
            for inp in form.select("input[type=hidden]"):
                if inp.get("name"):
                    data[inp["name"]] = inp.get("value", "")
        data[a.get("username_field", "username")] = user
        data[a.get("password_field", "password")] = pwd
        post_url = urljoin(login_url, form.get("action") or login_url) if form else login_url
        if urlparse(post_url).hostname != self.host:
            raise LoginError("le formulaire envoie vers un autre hôte : connexion refusée")
        self._logins += 1
        resp = self._request("POST", post_url, data=data)
        if not self._logged_in(resp):
            raise LoginError("connexion refusée (identifiants invalides ou protection supplémentaire)")

    def _ensure_session(self) -> None:
        if self.auth.get("type") == "form" and not self.session.cookies:
            self._login()

    # ------------------------------------------------------------ pages
    def _get_page(self, url: str):
        if not self._allowed(url):
            self._blocked += 1
            return None
        resp = self._request("GET", url)
        if self.auth.get("type") == "form" and not self._logged_in(resp):
            self.session.cookies.clear()                       # session expirée : une seule reconnexion
            self._login()
            resp = self._request("GET", url)
            if not self._logged_in(resp):
                raise LoginError("session refusée même après reconnexion")
        if resp.status_code >= 400:
            self._errors += 1
            return None
        return resp, BeautifulSoup(resp.text, "html.parser")

    def _list_articles(self) -> list[str]:
        links, url = [], urljoin(self.base + "/", self.list_url.lstrip("/"))
        for _ in range(self.max_pages):
            page = self._get_page(url)
            if not page:
                break
            resp, soup = page
            for a in soup.select(self.item_sel):
                href = urljoin(resp.url, a.get("href", ""))
                if urlparse(href).hostname == self.host and href not in links:
                    links.append(href)                         # on reste sur le site ciblé
            nxt = soup.select_one(self.next_sel) if self.next_sel else None
            if not nxt or not nxt.get("href"):
                break
            url = urljoin(resp.url, nxt["href"])
        return links

    # ------------------------------------------------------------ collecte
    def collect(self) -> Iterator[RawRecord]:
        self._failed = False
        try:
            self._ensure_session()
            todo = [u for u in self._list_articles() if u not in self.seen][: self.max_articles]
            for url in todo:
                if self._stopped:
                    break
                page = self._get_page(url)
                if not page:
                    continue
                _, soup = page
                node = soup.select_one(self.content_sel)
                if node is None:
                    self._errors += 1
                    continue
                zones = node.select(self.ioc_sel) if self.ioc_sel else [node]
                iocs = extract_iocs("\n".join(z.get_text(" ") for z in zones), self.ignore_domains)
                title_node = soup.select_one(self.title_sel) if self.title_sel else None
                title = title_node.get_text(" ", strip=True) if title_node else url
                self._articles += 1
                for kind, value in iocs:
                    self._emitted += 1
                    yield RawRecord(                           # content = uniquement l'indicateur
                        source_id=self.source_id, source_type=self.source_type, content=value,
                        metadata={"article_url": url, "article_title": title,
                                  "indicator_kind": kind, "origin": self.host})
                self.seen.append(url)
        except Exception:
            self._failed = True
            raise
        finally:
            self._save()

    def _save(self) -> None:
        cookies = requests.utils.dict_from_cookiejar(self.session.cookies)
        self._store.save({"cookies": cookies, "seen": self.seen[-5000:]})

    def health(self) -> HealthStatus:
        if self._failed:
            return HealthStatus(HealthState.DOWN, "connexion ou accès au site impossible")
        if self._errors or self._blocked:
            return HealthStatus(HealthState.DEGRADED,
                                f"{self._articles} articles, {self._errors} erreurs, "
                                f"{self._blocked} pages interdites par robots.txt")
        return HealthStatus(HealthState.OK, f"{self._articles} articles, {self._emitted} indicateurs")

    def stop(self) -> None:
        self._stopped = True
