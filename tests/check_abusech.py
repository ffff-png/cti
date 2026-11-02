"""Test hors-ligne de ThreatFox et URLhaus (API simulée, aucune clé requise)."""
import os
import tempfile
from unittest import mock

os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()

from collectors.abusech import ThreatFoxCollector, URLhausCollector
from core.collector import HealthState
from services.normalizer.main import normalize

TF = {"query_status": "ok", "data": [
    {"id": "1", "ioc": "203.0.113.9:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
     "malware_printable": "Cobalt Strike", "confidence_level": 75, "first_seen": "2026-10-30 09:10:23 UTC", "tags": ["cs"]},
    {"id": "2", "ioc": "Evil-C2.example", "ioc_type": "domain", "malware_printable": "Mirai",
     "confidence_level": 100, "first_seen": "2026-10-30 09:20:00 UTC"},
    {"id": "3", "ioc": "http://x.example/a.exe", "ioc_type": "url", "confidence_level": 50, "first_seen": "2026-10-30 09:30:00 UTC"},
    {"id": "4", "ioc": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash", "first_seen": "2026-10-30 09:40:00 UTC"},
    {"id": "5", "ioc": "999.1.1.1:80", "ioc_type": "ip:port", "first_seen": "2026-10-30 09:50:00 UTC"},
    {"id": "6", "ioc": "truc", "ioc_type": "autre", "first_seen": "2026-10-30 09:55:00 UTC"}]}
UH = {"query_status": "ok", "urls": [
    {"id": "10", "url": "http://203.0.113.50/bad.sh", "url_status": "online", "date_added": "2026-10-30 10:00:00 UTC", "threat": "malware_download", "tags": ["mirai"]},
    {"id": "11", "url": "http://old.example/x", "url_status": "offline", "date_added": "2026-10-30 09:00:00 UTC"},
    {"id": "12", "url": "ftp://pas-http", "url_status": "online", "date_added": "2026-10-30 09:30:00 UTC"}]}


def resp(body, code=200):
    r = mock.Mock(); r.json = lambda: body
    r.raise_for_status = (lambda: None) if code < 400 else mock.Mock(side_effect=RuntimeError(f"HTTP {code}"))
    return r


def run(cls, patch_name, body, cfg=None, code=200):
    c = cls(); c.configure(cfg or {})
    with mock.patch.dict(os.environ, {"ABUSECH_AUTH_KEY": "k"}), \
         mock.patch(f"collectors.abusech.requests.{patch_name}", return_value=resp(body, code)) as m:
        return c, list(c.collect()), m


# ThreatFox
c, recs, m = run(ThreatFoxCollector, "post", TF)
assert [r.content for r in recs] == ["203.0.113.9", "evil-c2.example", "http://x.example/a.exe",
                                     "d41d8cd98f00b204e9800998ecf8427e"], [r.content for r in recs]
assert recs[0].metadata["port"] == "443" and recs[0].metadata["malware"] == "Cobalt Strike"
assert m.call_args.kwargs["json"] == {"query": "get_iocs", "days": 1}
assert m.call_args.kwargs["headers"]["Auth-Key"] == "k" and c.health().state == HealthState.DEGRADED
for r in recs: normalize(r.to_dict(), "t")
print("ThreatFox : ip:port séparé, domaine/URL/hash, 2 invalides ignorés, normalisation STIX : OK")

c2, recs2, _ = run(ThreatFoxCollector, "post", TF)         # nouvelle instance = comme l'orchestrateur
assert recs2 == []
print("ThreatFox : curseur persistant, rien n'est republié aux collectes suivantes : OK")

TF2 = {"query_status": "ok", "data": TF["data"] + [
    {"id": "7", "ioc": "198.51.100.1:80", "ioc_type": "ip:port", "first_seen": "2026-10-31 08:00:00 UTC"}]}
_, recs3, m3 = run(ThreatFoxCollector, "post", TF2)
assert [r.content for r in recs3] == ["198.51.100.1"] and 1 <= m3.call_args.kwargs["json"]["days"] <= 7
print("ThreatFox : seul le nouvel IOC est publié, 'days' borné entre 1 et 7 : OK")

os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
_, hi, _ = run(ThreatFoxCollector, "post", TF, {"min_confidence": 80})
assert [r.content for r in hi] == ["evil-c2.example", "d41d8cd98f00b204e9800998ecf8427e"], [r.content for r in hi]
print("ThreatFox : filtre min_confidence : OK")

for body, label in (({"query_status": "unauthorized"}, "unauthorized"), ):
    os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
    try: run(ThreatFoxCollector, "post", body); raise SystemExit("erreur attendue")
    except RuntimeError as e: print("ThreatFox : statut d'erreur remonté :", e)
os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
c4 = ThreatFoxCollector(); c4.configure({})
with mock.patch.dict(os.environ, {}, clear=True):
    try: list(c4.collect()); raise SystemExit("erreur attendue")
    except RuntimeError as e: print("ThreatFox : clé absente :", e)
os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
_, none, _ = run(ThreatFoxCollector, "post", {"query_status": "no_result"})
assert none == []

# URLhaus
os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
c, recs, m = run(URLhausCollector, "get", UH)
assert [r.content for r in recs] == ["http://203.0.113.50/bad.sh", "http://old.example/x"]
assert "/urls/recent/limit/1000/" in m.call_args.args[0]
for r in recs: normalize(r.to_dict(), "t")
_, recs, _ = run(URLhausCollector, "get", UH)
assert recs == []
os.environ["CTI_STATE_DIR"] = tempfile.mkdtemp()
_, on, _ = run(URLhausCollector, "get", UH, {"only_online": True})
assert [r.content for r in on] == ["http://203.0.113.50/bad.sh"]
print("URLhaus : URL valides, only_online, curseur persistant, normalisation : OK")
