"""Test hors-ligne du collecteur OTX (API simulée, aucune clé requise)."""
import os
import tempfile
from unittest import mock

os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()

from collectors.otx import OTXCollector
from core.collector import HealthState
from services.normalizer.main import normalize

PAGE1 = {"next": "https://otx.alienvault.com/api/v1/pulses/subscribed?page=2", "results": [{
    "id": "p1", "name": "Campagne contre 198.51.100.99 et evil.example", "tags": ["apt"],
    "malware_families": [{"display_name": "Emotet"}], "attack_ids": [{"id": "T1566"}],
    "indicators": [
        {"indicator": "203.0.113.5", "type": "IPv4"},
        {"indicator": "Phish.Example.COM", "type": "domain"},
        {"indicator": "http://x.example/a", "type": "URL"},
        {"indicator": "user@x.example", "type": "email"},
        {"indicator": "999.1.1.1", "type": "IPv4"},
    ]}]}
PAGE2 = {"next": None, "results": [{"id": "p2", "name": "autre", "indicators": [
    {"indicator": "192.0.2.44", "type": "IPv4"}]}]}


def fake_get(url, params=None, **kw):
    r = mock.Mock(); r.raise_for_status = lambda: None
    r.json = lambda: PAGE2 if "page=2" in url else PAGE1
    return r


c = OTXCollector(); c.configure({})
with mock.patch.dict(os.environ, {"OTX_API_KEY": "test"}), \
     mock.patch("collectors.otx.requests.get", fake_get):
    recs = list(c.collect())
assert [r.content for r in recs] == ["203.0.113.5", "phish.example.com", "http://x.example/a", "192.0.2.44"], [r.content for r in recs]
assert c.health().state == HealthState.OK or c.health().state == HealthState.DEGRADED
print("Pagination + filtrage des types : OK (2 ignorés : e-mail, IP invalide)")

kinds = [normalize(r.to_dict(), "t").payload["name"] for r in recs]
assert kinds[1].startswith("domain-name") and kinds[2].startswith("url"), kinds
print("Normalisation (le nom de pulse contenant une IP ne perturbe pas) :", kinds)
assert c._since is not None
print("Curseur incrémental avancé : OK")

# l'orchestrateur recrée le collecteur à chaque collecte : le curseur doit survivre
calls = []
def spy_get(url, params=None, **kw):
    calls.append(params); return fake_get(url, params, **kw)
c_new = OTXCollector(); c_new.configure({})
assert c_new._since is not None
with mock.patch.dict(os.environ, {"OTX_API_KEY": "test"}), mock.patch("collectors.otx.requests.get", spy_get):
    list(c_new.collect())
from datetime import datetime, timedelta
sent = datetime.fromisoformat(calls[0]["modified_since"])
assert datetime.utcnow() - sent < timedelta(minutes=5), sent
print("Curseur conservé entre deux instances (plus de re-téléchargement de 7 jours) : OK")

c2 = OTXCollector(); c2.configure({})
with mock.patch.dict(os.environ, {}, clear=True):
    try: list(c2.collect()); raise SystemExit("erreur attendue")
    except RuntimeError as e: print("Clé absente détectée :", e)
assert c2.health().state == HealthState.DOWN

os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
c3 = OTXCollector(); c3.configure({})
with mock.patch.dict(os.environ, {"OTX_API_KEY": "x"}), \
     mock.patch("collectors.otx.requests.get", side_effect=ConnectionError("réseau")):
    try: list(c3.collect()); raise SystemExit("erreur attendue")
    except ConnectionError: pass
assert c3._since is None
print("Échec réseau : curseur non avancé, état DOWN : OK")
