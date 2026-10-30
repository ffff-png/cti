import json
from confluent_kafka import Producer


class KafkaPublisher:
    def __init__(self, bootstrap: str = "localhost:9092"):
        self._producer = Producer({
            "bootstrap.servers": bootstrap,
            "acks": "all",
            "enable.idempotence": True,
        })
        self.errors = 0

    def _on_delivery(self, err, msg):
        if err is not None:
            self.errors += 1
            print(f"[ERREUR] livraison échouée : {err}")

    def publish(self, topic: str, key: str, value: dict) -> None:
        self._producer.produce(
            topic,
            key=key.encode("utf-8"),
            value=json.dumps(value).encode("utf-8"),
            on_delivery=self._on_delivery,
        )
        self._producer.poll(0)

    def flush(self) -> None:
        self._producer.flush(10)
