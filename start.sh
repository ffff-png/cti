#!/usr/bin/env bash
# Relance toute la plateforme CTI (état de l'étape 7 : collecte + supervision)
# Usage : ./start.sh        depuis la racine du projet (~/cti-collector)
set -u
cd "$(dirname "$0")"

# 1. Environnement Python
if [ ! -d .venv ]; then
  echo "[!] .venv introuvable : python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
  exit 1
fi
source .venv/bin/activate

# Variables secrètes (clé OTX, etc.) exportées pour les services Python
set -a; [ -f .env ] && source .env; set +a

# Tor (optionnel) : TOR_ENABLED=1 dans .env pour démarrer le conteneur Tor
COMPOSE="docker compose -f docker-compose.yml"
[ -f docker-compose.tor.yml ] && COMPOSE="$COMPOSE -f docker-compose.tor.yml"
if [ "${TOR_ENABLED:-0}" = "1" ]; then
  if ! grep -q '^TOR_CONTROL_PASSWORD=.' .env 2>/dev/null; then
    echo "TOR_CONTROL_PASSWORD=$(openssl rand -hex 16)" >> .env     # mot de passe généré une seule fois
    set -a; source .env; set +a
  fi
  export COMPOSE_PROFILES=tor
  if [ ! -f docker-compose.tor.yml ]; then
    echo "[!] TOR_ENABLED=1 mais docker-compose.tor.yml est introuvable : Tor ne sera PAS démarré."
  fi
fi

# 2. Docker : Kafka, Redis, Prometheus, Grafana (+ Tor)
echo "[1/4] Démarrage de Docker..."
$COMPOSE up -d || { echo "[!] docker compose a échoué (Docker est-il lancé ?)"; exit 1; }

# 3. Attendre que Kafka réponde
echo "[2/4] Attente de Kafka..."
for i in $(seq 1 30); do
  docker exec cti-kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list >/dev/null 2>&1 && break
  sleep 2
  [ "$i" = 30 ] && { echo "[!] Kafka ne répond pas"; exit 1; }
done
[ "$(docker exec cti-redis redis-cli ping 2>/dev/null)" = "PONG" ] && echo "     Redis : PONG"

# 4. Topics (sans effet s'ils existent déjà)
echo "[3/4] Vérification des topics..."
for t in raw.x cti.pivot cti.normalized cti.near_duplicates ops.metrics dlq.normalizer dlq.deduplicator; do
  docker exec cti-kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
    --create --if-not-exists --topic "$t" --partitions 3 --replication-factor 1 >/dev/null
done

# 5. Services Python en arrière-plan (journaux dans logs/)
echo "[4/4] Lancement des services..."
mkdir -p logs .pids
for svc in normalizer deduplicator orchestrator; do
  if [ -f ".pids/$svc.pid" ] && kill -0 "$(cat .pids/$svc.pid)" 2>/dev/null; then
    echo "     $svc déjà en cours"; continue
  fi
  nohup python -u -m services.$svc.main > "logs/$svc.log" 2>&1 &
  echo $! > ".pids/$svc.pid"
  echo "     $svc lancé (PID $!)"
done

cat <<MSG

Plateforme démarrée.
  Grafana    : http://localhost:3000   (admin / mot de passe du fichier .env)
  Prometheus : http://localhost:9090/targets
  Journaux   : tail -f logs/orchestrator.log   (ou normalizer, deduplicator)
  Arrêt      : ./stop.sh
MSG
