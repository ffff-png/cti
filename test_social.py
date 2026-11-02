import yaml
import time
from collectors.x import XCollector
from collectors.facebook import FacebookCollector

def test_collector(name, collector_class, config_key):
    print(f"\n{'='*40}")
    print(f"🧪 TEST DU COLLECTEUR : {name.upper()}")
    print(f"{'='*40}")
    
    with open("config/social_collectors.yml", "r") as f:
        config = yaml.safe_load(f)
    
    if not config.get(config_key, {}).get("enabled"):
        print(f"⚠️  Le collecteur {name} est désactivé dans la config.")
        return

    collector = collector_class()
    collector.configure(config[config_key])

    print(f"🚀 Démarrage de la collecte {name}...")
    print("💡 La fenêtre restera ouverte 60 secondes après la collecte")
    
    count = 0
    try:
        for record in collector.collect():
            count += 1
            print(f"✅ [{count}] {record.content[:80]}...")
            if count >= 3:
                break
    except Exception as e:
        print(f"❌ ERREUR FATALE : {e}")
        import traceback
        traceback.print_exc()
    finally:
        print(f"\n🏁 Test terminé. {count} éléments récupérés.")
        print(f"🩺 État de santé : {collector.health()}")
        print("\n⏳ La fenêtre reste ouverte 60 secondes pour inspection...")
        print("   Appuyez sur Ctrl+C pour fermer immédiatement")
        try:
            time.sleep(60)  # Garde la fenêtre ouverte 60 secondes
        except KeyboardInterrupt:
            print("\n👋 Fermeture manuelle")

if __name__ == "__main__":
    test_collector("X", XCollector, "x")
    # test_collector("Facebook", FacebookCollector, "facebook")
