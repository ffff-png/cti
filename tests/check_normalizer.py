from services.normalizer.main import normalize, NormalizationError

raw = {
    "record_id": "r1", "source_id": "test", "source_type": "api",
    "content": "Adresse IP suspecte observée : 203.0.113.60",
    "metadata": {}, "collected_at": "2026-10-26T14:00:00+00:00",
}
a = normalize(raw, "kafka://raw.test/0/1")
b = normalize({**raw, "record_id": "r2",
               "content": "IP 203.0.113.60 signalée par une autre source"},
              "kafka://raw.test/0/2")
print("Type :", a.payload["type"], "|", a.payload["pattern"])
print("Même empreinte pour deux phrases différentes :",
      a.envelope.content_hash == b.envelope.content_hash)

try:
    normalize({**raw, "content": "rien d'utile ici"}, "x")
except NormalizationError as e:
    print("Rejet correct :", e)
