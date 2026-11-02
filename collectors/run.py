import argparse
import yaml
from pathlib import Path

from collectors.fake import FakeCollector
from collectors.x import XCollector
from collectors.facebook import FacebookCollector
from core.kafka_io import KafkaPublisher


def load_social_config(config_path: str = "config/social_collectors.yml") -> dict:
    """Charge la configuration des collecteurs sociaux."""
    path = Path(config_path)
    if not path.exists():
        print(f"⚠️  Fichier de config introuvable : {config_path}")
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def run_social_collectors(config: dict, topic: str, bootstrap: str):
    """Lance les collecteurs sociaux configurés (X et/ou Facebook)."""
    publisher = KafkaPublisher(bootstrap)
    collectors = []

    # Initialisation du collecteur X
    if config.get("x", {}).get("enabled", False):
        x_collector = XCollector()
        x_collector.configure(config["x"])
        collectors.append(x_collector)
        print("✅ Collecteur X initialisé")

    # Initialisation du collecteur Facebook
    if config.get("facebook", {}).get("enabled", False):
        fb_collector = FacebookCollector()
        fb_collector.configure(config["facebook"])
        collectors.append(fb_collector)
        print("✅ Collecteur Facebook initialisé")

    if not collectors:
        print("⚠️  Aucun collecteur social activé dans la config.")
        return

    # Boucle de collecte
    total_sent = 0
    try:
        for collector in collectors:
            print(f"\n🚀 Démarrage du collecteur : {collector.source_id}")
            for rec in collector.collect():
                publisher.publish(topic, key=rec.source_id, value=rec.to_dict())
                total_sent += 1
                print(f"   📨 [{rec.source_id}] {rec.content[:80]}...")
    except KeyboardInterrupt:
        print("\n⏹️  Arrêt demandé par l'utilisateur")
    except Exception as e:
        print(f"\n❌ Erreur lors de la collecte : {e}")
    finally:
        # Affichage des états de santé
        print("\n" + "=" * 50)
        print("📊 RAPPORT DE COLLECTE")
        print("=" * 50)
        for collector in collectors:
            print(f"  {collector.source_id} : {collector.health()}")
        print(f"\n  Total envoyés : {total_sent}")
        print(f"  Erreurs Kafka : {publisher.errors}")
        print("=" * 50)

        publisher.flush()


def run_fake_collector(count: int, topic: str, bootstrap: str):
    """Lance le collecteur de test (FakeCollector)."""
    collector = FakeCollector()
    collector.configure({"count": count})
    publisher = KafkaPublisher(bootstrap)

    for rec in collector.collect():
        publisher.publish(topic, key=rec.source_id, value=rec.to_dict())
        print(f"envoyé #{rec.metadata['seq']} : {rec.content}")

    publisher.flush()
    print("Santé :", collector.health())
    print("Erreurs de livraison :", publisher.errors)


def main():
    ap = argparse.ArgumentParser(description="Lanceur de collecteurs CTI")
    
    # Mode de fonctionnement
    ap.add_argument(
        "--mode", 
        choices=["fake", "social", "all"], 
        default="fake",
        help="Mode de collecte : 'fake' (test), 'social' (X/Facebook), 'all' (tous)"
    )
    
    # Arguments Kafka
    ap.add_argument("--topic", default="raw.test")
    ap.add_argument("--bootstrap", default="localhost:9092")
    
    # Arguments spécifiques
    ap.add_argument("--count", type=int, default=10, help="Nombre de records pour FakeCollector")
    ap.add_argument("--config", default="config/social_collectors.yml", help="Chemin vers la config sociale")
    
    args = ap.parse_args()

    print("=" * 50)
    print("🔍 CTI COLLECTOR - Démarrage")
    print("=" * 50)
    print(f"Mode : {args.mode}")
    print(f"Topic Kafka : {args.topic}")
    print(f"Bootstrap : {args.bootstrap}")
    print("=" * 50)

    # Exécution selon le mode choisi
    if args.mode == "fake":
        run_fake_collector(args.count, args.topic, args.bootstrap)
    
    elif args.mode == "social":
        social_config = load_social_config(args.config)
        run_social_collectors(social_config, args.topic, args.bootstrap)
    
    elif args.mode == "all":
        # Lance d'abord le fake, puis les sociaux
        run_fake_collector(args.count, args.topic, args.bootstrap)
        print("\n" + "=" * 50)
        social_config = load_social_config(args.config)
        run_social_collectors(social_config, args.topic, args.bootstrap)


if __name__ == "__main__":
    main()
