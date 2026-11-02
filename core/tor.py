"""Accès Tor : sessions HTTP via SOCKS (résolution DNS côté Tor), circuits isolés,
rotation par le port de contrôle. Principe : en cas de doute, on s'arrête (jamais de connexion directe)."""
import secrets
import socket
import time

import requests

GENERIC_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept": "text/html,text/plain;q=0.9,*/*;q=0.5",
}


class TorError(RuntimeError):
    pass


class TorUnavailable(TorError):
    pass


class TorLeak(TorError):
    pass


def _addr(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host, int(port)


class TorClient:
    def __init__(self, socks="127.0.0.1:9050", control="127.0.0.1:9051", control_password=None,
                 check_url="https://check.torproject.org/api/ip", min_newnym_interval=10.0):
        self.socks, self.control = socks, control
        self.password = control_password
        self.check_url = check_url
        self.min_interval = min_newnym_interval
        self._last_newnym = 0.0

    def ensure_reachable(self) -> None:
        try:
            socket.create_connection(_addr(self.socks), timeout=5).close()
        except OSError as exc:
            raise TorUnavailable(f"proxy Tor injoignable ({self.socks}) : arrêt, aucune connexion directe") from exc

    def session(self) -> requests.Session:
        """Nouvelle session = nouvelle identité SOCKS = circuit dédié (IsolateSOCKSAuth).
        « socks5h » : le nom .onion est résolu par Tor, jamais par cette machine."""
        proxy = f"socks5h://{secrets.token_hex(8)}:{secrets.token_hex(4)}@{self.socks}"
        s = requests.Session()
        s.trust_env = False                       # ignorer HTTP(S)_PROXY de l'environnement
        s.proxies = {"http": proxy, "https": proxy}
        s.headers.update(GENERIC_HEADERS)
        return s

    def verify_exit(self, session: requests.Session) -> None:
        """Vérifie que le trafic sort bien par Tor (sinon : fuite possible)."""
        try:
            data = session.get(self.check_url, timeout=60).json()
        except Exception as exc:
            raise TorUnavailable(f"vérification Tor impossible : {exc}") from exc
        if not data.get("IsTor"):
            raise TorLeak("le trafic ne sort pas par Tor : arrêt")

    def new_identity(self) -> None:
        """Demande de nouveaux circuits (SIGNAL NEWNYM) ; Tor impose ~10 s entre deux demandes."""
        if not self.password:
            raise TorError("mot de passe du port de contrôle absent (TOR_CONTROL_PASSWORD)")
        wait = self.min_interval - (time.time() - self._last_newnym)
        if wait > 0:
            time.sleep(wait)
        pwd = self.password.replace("\\", "\\\\").replace('"', '\\"')
        try:
            with socket.create_connection(_addr(self.control), timeout=10) as sock:
                f = sock.makefile("rw", newline="\r\n")
                for cmd in (f'AUTHENTICATE "{pwd}"', "SIGNAL NEWNYM"):
                    f.write(cmd + "\r\n"); f.flush()
                    reply = f.readline()
                    if not reply.startswith("250"):
                        raise TorError(f"port de contrôle : {reply.strip() or 'pas de réponse'}")
                f.write("QUIT\r\n"); f.flush()
        except OSError as exc:
            raise TorError(f"port de contrôle injoignable : {exc}") from exc
        self._last_newnym = time.time()
