#!/bin/sh
set -eu
: "${TOR_CONTROL_PASSWORD:?TOR_CONTROL_PASSWORD manquant (voir .env)}"
HASH="$(tor --hash-password "$TOR_CONTROL_PASSWORD" | tail -n 1)"
{
  cat /etc/tor/torrc.base
  echo "HashedControlPassword $HASH"
  # Chaîne de proxys : passer d'abord par un proxy SOCKS5 amont (VPN / proxy de l'institution)
  if [ -n "${TOR_UPSTREAM_SOCKS5:-}" ]; then echo "Socks5Proxy $TOR_UPSTREAM_SOCKS5"; fi
  # Ponts (si Tor est bloqué sur le réseau) : fichier monté, voir docker-compose.tor.yml
  if [ -f /etc/tor/bridges.conf ]; then cat /etc/tor/bridges.conf; fi
} > /tmp/torrc
exec tor -f /tmp/torrc
