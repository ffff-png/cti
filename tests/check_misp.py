"""Test du collecteur MISP contre un faux serveur MISP local (vraies requêtes HTTP)."""
import os
import tempfile
import threading
import time

os.environ["NO_PROXY"] = "127.0.0.1"
os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
os.environ["T_MISP"] = "cle-demo-misp"

from collectors.misp import MISPCollector
from core.collector import HealthState
from services.normalizer.main import normalize
from tools.demo_misp import make_server

srv = make_server()
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}"


def run(**o):
    c = MISPCollector(); c.source_id = "misp"
    c.configure({"base_url": BASE, "api_key_env": "T_MISP", **o})
    return c, list(c.collect())


# 1. collecte, composés et valeurs invalides
c, recs = run()
vals = sorted(r.content for r in recs)
assert vals == sorted(["203.0.113.5", "198.51.100.7", "evil.example", "192.0.2.10", "http://bad.example/x.php",
                       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                       "d41d8cd98f00b204e9800998ecf8427e"]), vals
assert [r.metadata["port"] for r in recs if r.content == "198.51.100.7"] == ["8080"]
assert "203.0.113.200" not in vals                          # attribut non IDS exclu
assert c.health().state == HealthState.DEGRADED             # 1 valeur invalide (999.1.1.1)
for r in recs: normalize(r.to_dict(), "t")
print("1. ip|port, domain|ip, filename|hash séparés ; invalide ignoré ; non-IDS exclu ; STIX valide : OK")

# 2. requête envoyée à MISP
req = srv.requests[0]
b = req["body"]
assert req["auth"] == "cle-demo-misp" and b["returnFormat"] == "json"
assert b["to_ids"] == 1 and b["enforceWarninglist"] == 1 and b["published"] == 1
assert "ip-dst" in b["type"]["OR"] and b["timestamp"] <= srv.now
print("2. Clé en-tête Authorization, to_ids, enforceWarninglist (valeurs bénignes retirées), type OR : OK")

# 3. curseur persistant : rien de nouveau, puis un nouvel attribut seulement
n = len(srv.requests)
_, again = run()
assert again == [] and srv.requests[n]["body"]["timestamp"] > b["timestamp"]
srv.attributes.append({"id": "99", "event_id": "2", "type": "ip-dst", "category": "x", "value": "203.0.113.99",
                       "to_ids": True, "timestamp": str(int(time.time()) + 5), "comment": ""})
_, new = run()
assert [r.content for r in new] == ["203.0.113.99"]
print("3. Curseur persistant : seul le nouvel attribut est publié : OK")

# 4. pagination
os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
n = len(srv.requests)
_, recs = run(limit=2)
pages = [r["body"]["page"] for r in srv.requests[n:]]
assert pages[:3] == [1, 2, 3] and len(recs) >= 8, (pages, len(recs))
print(f"4. Pagination (limit=2) : pages {pages} lues, rien de perdu : OK")

# 5. erreurs
os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
os.environ["T_MISP"] = "mauvaise-cle"
c = MISPCollector(); c.source_id = "misp"; c.configure({"base_url": BASE, "api_key_env": "T_MISP"})
try: list(c.collect()); raise SystemExit("erreur attendue")
except Exception as e: assert "403" in str(e)
assert c.health().state == HealthState.DOWN
os.environ.pop("T_MISP")
c = MISPCollector(); c.configure({"base_url": BASE, "api_key_env": "T_MISP"})
try: list(c.collect()); raise SystemExit("erreur attendue")
except RuntimeError as e: print("5. Clé refusée (403) -> DOWN ; clé absente :", e)
srv.shutdown()
