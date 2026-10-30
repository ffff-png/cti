import argparse
import ipaddress
import json
import re
import time
from datetime import datetime

import stix2
from confluent_kafka import Consumer

from core.kafka_io import KafkaPublisher
from core.metrics import start_metrics_server, NORMALIZED   # <-- AJOUT
from core.schema import SourceType, make_record, validate_record

IN_PATTERN = r"^raw\..*"
OUT_TOPIC = "cti.pivot"
DLQ_TOPIC = "dlq.normalizer"

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


class NormalizationError(Exception):
    pass


def extract_observable(text: str) -> tuple[str, str]:
    """Retourne (type STIX, valeur) : une IPv4 valide, sinon un domaine."""
    for m in IP_RE.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group())
        except ValueError:
            continue
        return "ipv4-addr", str(ip)
    m = DOMAIN_RE.search(text)
    if m:
        return "domain-name", m.group().lower()
    raise NormalizationError("aucun indicateur (IP ou domaine) trouvé")


def normalize(raw: dict, ref: str):
    for key in ("record_id", "source_id", "source_type", "content", "collected_at"):
        if key not in raw:
            raise NormalizationError(f"champ manquant : {key}")
    try:
        stype = SourceType(raw["source_type"])
    except ValueError:
        raise NormalizationError(f"source_type inconnu : {raw['source_type']}")

    kind, value = extract_observable(raw["content"])
    indicator = stix2.Indicator(
        name=f"{kind} : {value}",
        description=raw["content"],
        pattern=f"[{kind}:value = '{value}']",
        pattern_type="stix",
    )
    rec = make_record(
        source_id=raw["source_id"],
        source_type=stype,
        canonical_text=f"{kind}:{value}",
        stix_obj=indicator,
        reliability="C",
        collector_version="normalizer-0.1.0",
        raw_ref=ref,
    )
    # on garde l'identifiant et la date d'origine pour la traçabilité
    rec.envelope.record_id = raw["record_id"]
    rec.envelope.collected_at = datetime.fromisoformat(raw["collected_at"])

    validate_record(rec.model_dump(mode="json"))   # garde-fou final
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", default="localhost:9092")
    ap.add_argument("--group", default="normalizer")
    ap.add_argument("--once", action="store_true",
                    help="s'arrête quand il n'y a plus de messages")
    ap.add_argument("--idle", type=int, default=10,
                    help="secondes sans message avant l'arrêt (avec --once)")
    ap.add_argument("--metrics-port", type=int, default=8002)   # <-- AJOUT
    args = ap.parse_args()
    start_metrics_server(args.metrics_port)                     # <-- AJOUT

    consumer = Consumer({
        "bootstrap.servers": args.bootstrap,
        "group.id": args.group,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    })
    consumer.subscribe([IN_PATTERN])
    pub = KafkaPublisher(args.bootstrap)

    stats = {"ok": 0, "dlq": 0}
    last_msg = time.time()
    print("Normalisation démarrée (Ctrl+C pour arrêter)")
    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                if args.once and time.time() - last_msg > args.idle:
                    break
                continue
            if msg.error():
                print("[avertissement]", msg.error())
                continue
            last_msg = time.time()

            ref = f"kafka://{msg.topic()}/{msg.partition()}/{msg.offset()}"
            try:
                raw = json.loads(msg.value())
                rec = normalize(raw, ref)
                pub.publish(OUT_TOPIC, key=rec.envelope.source_id,
                            value=rec.model_dump(mode="json"))
                stats["ok"] += 1
                NORMALIZED.labels(result="ok").inc()            # <-- AJOUT
                print(f"OK  {ref} -> {rec.payload['name']}")
            except Exception as exc:
                value = msg.value()
                pub.publish(DLQ_TOPIC,
                            key=msg.key().decode("utf-8", "replace") if msg.key() else "unknown",
                            value={
                                "stage": "normalizer",
                                "error": str(exc),
                                "ref": ref,
                                "raw": value.decode("utf-8", "replace") if value else None,
                            })
                stats["dlq"] += 1
                NORMALIZED.labels(result="dlq").inc()           # <-- AJOUT
                print(f"DLQ {ref} : {exc}")

            pub.flush()
            consumer.commit(message=msg, asynchronous=False)
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()
    print(f"Terminé : {stats['ok']} normalisés, {stats['dlq']} en erreur (DLQ)")


if __name__ == "__main__":
    main()
