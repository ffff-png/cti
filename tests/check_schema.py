import stix2
from core.schema import make_record, validate_record, SourceType

ind = stix2.Indicator(
    name="IP de test",
    pattern="[ipv4-addr:value = '203.0.113.5']",
    pattern_type="stix",
)
rec = make_record("test", SourceType.API, "203.0.113.5", ind)
validate_record(rec.model_dump(mode="json"))
print("Message valide :", rec.envelope.content_hash)

try:
    validate_record({"envelope": {"source_id": "x"}, "payload": {}})
except Exception:
    print("Message invalide rejeté : OK")
