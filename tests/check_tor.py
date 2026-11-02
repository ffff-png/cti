"""Test du collecteur Tor avec un FAUX proxy SOCKS5 et un FAUX port de contrôle (aucun vrai Tor)."""
import json
import os
import socket
import socketserver
import tempfile
import threading
from unittest import mock

os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
os.environ["T_CTL"] = "motdepasse"

from collectors.onion import OnionCollector
from core.collector import HealthState
from core.tor import TorClient, TorLeak, TorUnavailable
from services.normalizer.main import normalize

H1, H2 = "a" * 56 + ".onion", "b" * 56 + ".onion"
CHECK = "check.torproject.org"
PAGES = {   # hôte -> (type, corps)
    H1: ("text/html", "<p>C2 : hxxp://evil-c2[.]example/gate 203.0.113.7</p><script>var ip='198.51.100.9';</script>"),
    H2: ("text/plain", "bad-domain[.]example d41d8cd98f00b204e9800998ecf8427e"),
    CHECK: ("application/json", json.dumps({"IsTor": True, "IP": "1.2.3.4"})),
}
SEEN = {"atyp": [], "hosts": [], "users": []}


def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        part = sock.recv(n - len(buf))
        if not part: raise ConnectionError
        buf += part
    return buf


class Socks5(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        try:
            _, n = recvn(s, 2); recvn(s, n)
            s.sendall(b"\x05\x02")                                   # authentification par identifiants
            recvn(s, 1); user = recvn(s, recvn(s, 1)[0]).decode(); recvn(s, recvn(s, 1)[0])
            s.sendall(b"\x01\x00"); SEEN["users"].append(user)
            _, _, _, atyp = recvn(s, 4); SEEN["atyp"].append(atyp)
            host = recvn(s, recvn(s, 1)[0]).decode() if atyp == 3 else socket.inet_ntoa(recvn(s, 4))
            recvn(s, 2); SEEN["hosts"].append(host)
            s.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            req = b""
            while b"\r\n\r\n" not in req: req += s.recv(4096)
            path = req.split(b" ")[1].decode()
            ctype, body = PAGES.get(host, ("text/plain", "")) if path != "/img" else ("image/png", "PNG")
            if path == "/big": body = "x " * 3000 + "203.0.113.99"
            if path == "/redir":
                s.sendall(b"HTTP/1.1 302 Found\r\nLocation: http://evil.example/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); return
            data = body.encode()
            s.sendall(f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)
        except (ConnectionError, OSError):
            pass


class Control(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            cmd = line.decode().strip()
            if cmd.startswith("AUTHENTICATE"):
                ok = cmd == 'AUTHENTICATE "motdepasse"'
                self.wfile.write(b"250 OK\r\n" if ok else b"515 Authentication failed\r\n")
            elif cmd == "SIGNAL NEWNYM":
                self.server.newnym += 1; self.wfile.write(b"250 OK\r\n")
            elif cmd == "QUIT":
                self.wfile.write(b"250 closing\r\n"); return


class TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True; daemon_threads = True


socks, ctl = TS(("127.0.0.1", 0), Socks5), TS(("127.0.0.1", 0), Control)
ctl.newnym = 0
for srv in (socks, ctl): threading.Thread(target=srv.serve_forever, daemon=True).start()
SOCKS = f"127.0.0.1:{socks.server_address[1]}"
CTL = f"127.0.0.1:{ctl.server_address[1]}"
os.environ["NO_PROXY"] = "127.0.0.1"


def cfg(**o):
    c = {"socks": SOCKS, "control": CTL, "control_password_env": "T_CTL", "delay": [0, 0],
         "min_newnym_interval": 0, "check_url": f"http://{CHECK}/api/ip",
         "targets": [{"url": f"http://{H1}/", "name": "site1"}, {"url": f"http://{H2}/", "name": "site2"}]}
    c.update(o); return c


def run(**o):
    c = OnionCollector(); c.configure(cfg(**o)); return c, list(c.collect())


# 1. mécanismes Tor : résolution à distance, circuits isolés
t = TorClient(socks=SOCKS, check_url=f"http://{CHECK}/api/ip")
s1, s2 = t.session(), t.session()
assert s1.proxies["http"] != s2.proxies["http"] and s1.proxies["http"].startswith("socks5h://")
t.verify_exit(s1)
assert 3 in SEEN["atyp"] and 1 not in SEEN["atyp"], SEEN["atyp"]
print("1. socks5h : le nom d'hôte part vers Tor, aucune résolution DNS locale (pas de fuite) : OK")

# 2. collecte de bout en bout
SEEN["users"].clear(); ctl.newnym = 0
c, recs = run(rotate_every=1)
vals = sorted(r.content for r in recs)
assert vals == sorted(["http://evil-c2.example/gate", "203.0.113.7", "bad-domain.example",
                       "d41d8cd98f00b204e9800998ecf8427e"]), vals
assert "198.51.100.9" not in vals                                  # le contenu des <script> est ignoré
assert all(set(r.metadata) == {"target", "onion_host", "indicator_kind", "origin"} for r in recs)
for r in recs: normalize(r.to_dict(), "t")
print("2. Collecte .onion : IOC extraits, scripts ignorés, texte de page non conservé, STIX valide : OK")

# 3. rotation + circuits séparés
assert ctl.newnym == 1
assert len(set(SEEN["users"])) >= 3                                # vérif. + une identité par bloc
print("3. Rotation (NEWNYM) et nouvelle identité SOCKS par bloc : OK")

# 4. pages inchangées
_, again = run()
assert again == []
print("4. Page inchangée : rien n'est republié : OK")

# 5. mauvais mot de passe de contrôle : non fatal
os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
os.environ["T_CTL"] = "faux"
c, recs = run(rotate_every=1)
assert len(recs) == 4 and c.health().state == HealthState.DEGRADED and c._rotation_failures == 1
os.environ["T_CTL"] = "motdepasse"
print("5. Rotation impossible : collecte poursuivie, état DEGRADED : OK")

# 6. refus : type de contenu, redirection hors liste, gros fichier
os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
c = OnionCollector()
c.configure(cfg(targets=[{"url": f"http://{H1}/img"}, {"url": f"http://{H1}/redir"}, {"url": f"http://{H2}/big"}], max_bytes=1000))
recs = list(c.collect())
assert c._blocked == 2 and c._truncated == 1 and recs == [], (c._blocked, c._truncated, recs)
print("6. Image refusée, redirection hors liste blanche refusée, page géante tronquée : OK")

# 7. configuration refusée
for bad in ([], [{"url": "http://example.com/"}], [{"url": "http://" + "a" * 16 + ".onion/"}]):
    try: OnionCollector().configure(cfg(targets=bad)); raise SystemExit("refus attendu")
    except ValueError: pass
print("7. Liste vide, site non-.onion, ancienne adresse .onion v2 : refusés : OK")

# 8. Tor injoignable ou fuite : arrêt sans connexion directe
c = OnionCollector(); c.configure(cfg(socks="127.0.0.1:1"))
try: list(c.collect()); raise SystemExit("arrêt attendu")
except TorUnavailable: pass
assert c.health().state == HealthState.DOWN
PAGES[CHECK] = ("application/json", json.dumps({"IsTor": False}))
c = OnionCollector(); c.configure(cfg())
try: list(c.collect()); raise SystemExit("arrêt attendu")
except TorLeak: pass
print("8. Tor injoignable ou trafic hors Tor : arrêt immédiat, aucune connexion directe : OK")
socks.shutdown(); ctl.shutdown()
