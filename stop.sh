#!/usr/bin/env bash
# Arrête proprement les services Python, puis Docker (les données sont conservées)
cd "$(dirname "$0")"
for svc in orchestrator normalizer deduplicator; do
  if [ -f ".pids/$svc.pid" ]; then
    kill "$(cat .pids/$svc.pid)" 2>/dev/null && echo "$svc arrêté"
    rm -f ".pids/$svc.pid"
  fi
done
docker compose stop
echo "Tout est arrêté. Relancez avec ./start.sh"
