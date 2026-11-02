"""Test 8b : URL, hash de fichiers, IPv6 dans le normalisateur."""
from services.normalizer.main import extract_observable, normalize, NormalizationError

def raw(c): return {"record_id": "r", "source_id": "t", "source_type": "api", "content": c,
                    "metadata": {}, "collected_at": "2026-10-30T10:00:00+00:00"}

cases = {
    "203.0.113.5": "ipv4-addr",
    "2001:db8::1": "ipv6-addr",
    "evil.example.com": "domain-name",
    "http://evil.example.com/a.php?x=1": "url",
    "d41d8cd98f00b204e9800998ecf8427e": "file-md5",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": "file-sha1",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "file-sha256",
    "Adresse IP suspecte observée : 203.0.113.60": "ipv4-addr",      # ancien comportement
}
for text, expected in cases.items():
    kind, _ = extract_observable(text)
    assert kind == expected, (text, kind)
    rec = normalize(raw(text), "t")                 # valide aussi le motif STIX
    print(f"{kind:12} OK  {rec.payload['pattern'][:70]}")

a = normalize(raw("HTTP://Evil.example.com/A"), "t")
assert "'" not in normalize(raw("http://x.example/a'b"), "t").payload["pattern"].split("=")[1][2:-2].replace("\\'", "")
print("Apostrophe dans une URL échappée : OK")
try: normalize(raw("rien d'utile"), "t"); raise SystemExit("rejet attendu")
except NormalizationError: print("Rejet du contenu sans indicateur : OK")
