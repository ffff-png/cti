"""Test de bout en bout du collecteur de site contre le site de démonstration local."""
import os
import tempfile
import threading

os.environ["NO_PROXY"] = "127.0.0.1,localhost"
os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
os.environ["T_USER"], os.environ["T_PASS"] = "analyste", "demo123"

from collectors.site import LoginError, SiteCollector
from core.collector import HealthState
from services.normalizer.main import normalize
from tools.demo_site import make_server

srv = make_server()
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}"


def cfg(**over):
    c = {"base_url": BASE, "list_url": "/", "item_selector": "a.title", "next_selector": "a.next",
         "content_selector": "div.article-body", "title_selector": "h1", "ioc_selector": "pre.iocs",
         "max_pages": 3, "delay": [0, 0], "backoff": 0.01, "ignore_domains": ["partner.example"],
         "auth": {"type": "form", "login_url": "/login", "username_env": "T_USER",
                  "password_env": "T_PASS", "success_selector": "a.logout"}}
    c.update(over)
    return c


def run(**over):
    c = SiteCollector(); c.source_id = "demo-site"; c.configure(cfg(**over))
    return c, list(c.collect())


# 1. première collecte : connexion, pagination, robots.txt, 429, sites externes
c, recs = run()
vals = sorted(r.content for r in recs)
expected = sorted(["http://evil-c2.example/gate.php", "203.0.113.77", "bad-domain.example",
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                   "198.51.100.23", "d41d8cd98f00b204e9800998ecf8427e",
                   "192.0.2.99", "second-domain.example"])
assert vals == expected, vals
assert srv.logins == 1
assert "/private/x" not in srv.hits, "robots.txt non respecté"
assert srv.state["a3_throttled"] and "/a/3" in srv.hits
assert not any("other.example" in h for h in srv.hits)
assert c.health().state == HealthState.DEGRADED          # 1 page interdite par robots.txt
print(f"1. Connexion CSRF, pagination, robots.txt, reprise après 429 : OK ({len(recs)} IOC)")
for r in recs:
    normalize(r.to_dict(), "t")
print("   Tous les IOC passent le normalisateur STIX : OK")

# 2. deuxième collecte (nouvelle instance) : cookies et articles lus rechargés
hits_before = len(srv.hits)
c, recs = run()
assert recs == [] and srv.logins == 1
assert not any(h.startswith("/a/") for h in srv.hits[hits_before:])
print("2. Session réutilisée, aucun article relu, aucune reconnexion : OK")

# 3. session expirée côté serveur + nouvel article : reconnexion automatique
srv.sessions.clear()
srv.articles["5"] = ("Nouveau", '<pre class="iocs">203.0.113.200</pre>')
c, recs = run(max_pages=3)
assert [r.content for r in recs] == ["203.0.113.200"] and srv.logins == 2
print("3. Session expirée détectée, reconnexion automatique unique : OK")

# 4. mauvais mot de passe : une seule tentative, pas d'acharnement
os.environ["T_PASS"] = "faux"
os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
c = SiteCollector(); c.source_id = "demo-site"; c.configure(cfg())
try: list(c.collect()); raise SystemExit("LoginError attendue")
except LoginError: pass
assert srv.failed_logins == 1 and c.health().state == HealthState.DOWN
print("4. Mauvais mot de passe : 1 seule tentative (anti-verrouillage), état DOWN : OK")

# 5. identifiants absents et HTTP distant refusé
os.environ.pop("T_PASS")
c = SiteCollector(); c.source_id = "x"; c.configure(cfg())
try: list(c.collect()); raise SystemExit("LoginError attendue")
except LoginError as e: print("5. Identifiants absents refusés :", e)
os.environ["T_PASS"] = "demo123"
c = SiteCollector(); c.source_id = "y"; c.configure(cfg(base_url="http://intel.example.org"))
try: list(c.collect()); raise SystemExit("LoginError attendue")
except LoginError as e: print("   Mot de passe en clair sur HTTP distant refusé :", e)
srv.shutdown()
