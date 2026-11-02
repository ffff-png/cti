# Fichier : main.py (à la racine de ~/cti-collector/)

import logging
from collectors.x import XCollector

# Import de votre producteur Kafka (assurez-vous que ce fichier existe)
from core.kafka_producer import CTIKafkaProducer

# Configuration du logging pour voir ce qui se passe
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def run_collection_pipeline():
    logging.info("🚀 Démarrage du pipeline de collecte CTI...")
    
    # 1. Initialisation du collecteur X
    collector = XCollector()
    config_x = {
        "keywords": ["ransomware", "cyberattack"],
        "max_posts": 10,
        "accounts_db": "accounts.db"  # Le fichier créé par twscrape
    }
    collector.configure(config_x)
    
    # 2. Initialisation du producteur Kafka
    # Adaptez "localhost:9092" si votre broker Kafka est ailleurs
    producer = CTIKafkaProducer(topic="cti_raw_social", bootstrap_servers="localhost:9092")
    
    try:
        logging.info("📡 Début de l'extraction des données...")
        
        # 3. Boucle de collecte et d'envoi
        count = 0
        for record in collector.collect():
            count += 1
            logging.info(f"📤 Envoi à Kafka [{count}] : {record.metadata.get('author')} - {record.content[:50]}...")
            
            # Envoi de l'objet RawRecord au broker Kafka
            producer.send(record)
            
        logging.info(f"✅ Collecte terminée avec succès. {count} éléments envoyés au broker.")
        
    except Exception as e:
        logging.error(f"❌ Erreur critique dans le pipeline : {e}")
    finally:
        # Nettoyage propre des ressources
        collector.stop()
        logging.info("🛑 Pipeline arrêté proprement.")

if __name__ == "__main__":
    run_collection_pipeline()
