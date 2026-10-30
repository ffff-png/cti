import argparse
import json
import time

import redis
from confluent_kafka import Consumer
from simhash import Simhash

from core.kafka_io import KafkaPublisher
from core.metrics import DEDUP, start_metrics_server

IN_TOPIC = "cti.pivot"
OUT_TOPIC = "cti.normalized"
NEAR_TOPIC = "cti.near_duplicates"
DLQ_TOPIC = "dlq.deduplicator"

METRIC_LABEL = {"unique": "unique", "exact": "exact_duplicate", "near": "near_duplicate"}

BANDS = 4          # 4 morceaux de 16 bits = 64 bits
BAND_BITS = 16


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


class Deduplicator:
    def __init__(self, r, ttl=7 * 24 * 3600, min_len=200, max_dist=3):
        self.r = r
        self.ttl = ttl
        self.min_len = min_len
        self.max_dist = max_dist

    @staticmethod
    def _text(rec: dict) -> str:
        return rec["payload"].get("description", "") or ""

    @staticmethod
    def _bands(value: int):
        mask = (1 << BAND_BITS) - 1
        return [(i, (value >> (i * BAND_BITS)) & mask) for i in range(BANDS)]

    def classify(self, rec: dict):
        """Retourne ('exact' | 'near' | 'unique', infos). N'écrit rien dans Redis,
        sauf le compteur de recoupements d'un doublon exact."""
        h = rec["envelope"]["content_hash"]

        # Niveau 1 : doublon exact
        if self.r.exists(f"dedup:exact:{h}"):
            seen = self.r.incr(f"dedup:seen:{h}")
            self.r.expire(f"dedup:seen:{h}", self.ttl)
            return "exact", {"first_record": self.r.get(f"dedup:exact:{h}"),
                             "seen": seen}

        # Niveau 2 : quasi-doublon (textes longs uniquement)
        text = self._text(rec)
        if len(text) >= self.min_len:
            value = Simhash(text).value
            candidates = set()
            for i, band in self._bands(value):
                candidates |= self.r.smembers(f"dedup:sh:{i}:{band}")
            best = None
            for cand in candidates:
                cand_hex, cand_id = cand.split(":", 1)
                d = hamming(value, int(cand_hex, 16))
                if d <= self.max_dist and (best is None or d < best[0]):
                    best = (d, cand_id)
            if best:
                return "near", {"similar_to": best[1], "distance": best[0]}

        return "unique", {}

    def register(self, rec: dict) -> None:
        """À appeler seulement après la publication réussie d'un message unique."""
        h = rec["envelope"]["content_hash"]
        rid = rec["envelope"]["record_id"]
        pipe = self.r.pipeline()
        pipe.set(f"dedup:exact:{h}", rid, ex=self.ttl)
        pipe.set(f"dedup:seen:{h}", 1, ex=self.ttl)
        text = self._text(rec)
        if len(text) >= self.min_len:
            value = Simhash(text).value
            member = f"{value:016x}:{rid}"
            for i, band in self._bands(value):
                key = f"dedup:sh:{i}:{band}"
                pipe.sadd(key, member)
                pipe.expire(key, self.ttl)
        pipe.execute()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bootstrap", default="localhost:9092")
    ap.add_argument("--redis-host", default="localhost")
    ap.add_argument("--group", default="deduplicator")
    ap.add_argument("--ttl-days", type=float, default=7)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--idle", type=int, default=10)
    ap.add_argument("--metrics-port", type=int, default=8003)
    args = ap.parse_args()
    start_metrics_server(args.metrics_port)

    r = redis.Redis(host=args.redis_host, decode_responses=True)
    dedup = Deduplicator(r, ttl=int(args.ttl_days * 86400))

    consumer = Consumer({
        "bootstrap.servers": args.bootstrap,
        "group.id": args.group,
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    })
    consumer.subscribe([IN_TOPIC])
    pub = KafkaPublisher(args.bootstrap)

    stats = {"unique": 0, "exact": 0, "near": 0, "dlq": 0}
    last_msg = time.time()
    print("Déduplication démarrée (Ctrl+C pour arrêter)")
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
                rec = json.loads(msg.value())
                status, info = dedup.classify(rec)
                key = rec["envelope"]["source_id"]

                if status == "unique":
                    pub.publish(OUT_TOPIC, key=key, value=rec)
                    pub.flush()
                    dedup.register(rec)          # après la publication
                    print(f"UNIQUE  {rec['payload']['name']}")
                elif status == "exact":
                    print(f"EXACT   {rec['payload']['name']} "
                          f"(vu {info['seen']} fois, premier : {info['first_record']})")
                else:
                    pub.publish(NEAR_TOPIC, key=key,
                                value={"record": rec, "dedup": info})
                    pub.flush()
                    print(f"QUASI   similaire à {info['similar_to']} "
                          f"(distance {info['distance']})")
                stats[status] += 1
                DEDUP.labels(result=METRIC_LABEL[status]).inc()
            except Exception as exc:
                value = msg.value()
                pub.publish(DLQ_TOPIC, key="unknown", value={
                    "stage": "deduplicator", "error": str(exc), "ref": ref,
                    "raw": value.decode("utf-8", "replace") if value else None,
                })
                pub.flush()
                stats["dlq"] += 1
                DEDUP.labels(result="error").inc()
                print(f"DLQ {ref} : {exc}")

            consumer.commit(message=msg, asynchronous=False)
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()
    print("Terminé :", stats)


if __name__ == "__main__":
    main()
