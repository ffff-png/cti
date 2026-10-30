import argparse

from collectors.fake import FakeCollector
from core.kafka_io import KafkaPublisher


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--topic", default="raw.test")
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--bootstrap", default="localhost:9092")
    args = ap.parse_args()

    collector = FakeCollector()
    collector.configure({"count": args.count})
    publisher = KafkaPublisher(args.bootstrap)

    for rec in collector.collect():
        publisher.publish(args.topic, key=rec.source_id, value=rec.to_dict())
        print(f"envoyé #{rec.metadata['seq']} : {rec.content}")

    publisher.flush()
    print("Santé :", collector.health())
    print("Erreurs de livraison :", publisher.errors)


if __name__ == "__main__":
    main()
