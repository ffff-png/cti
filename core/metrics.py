from prometheus_client import Counter, Gauge, Histogram, start_http_server

# --- Orchestrateur / collecteurs ---
COLLECTIONS = Counter("cti_collections_total", "Collectes terminées", ["source", "status"])
COLLECTED = Counter("cti_collected_messages_total", "Messages bruts collectés", ["source"])
COLLECT_DURATION = Histogram("cti_collect_duration_seconds", "Durée d'une collecte", ["source"])
# 0=OK 1=DEGRADED 2=SUSPENDED 3=DISABLED
SOURCE_STATE = Gauge("cti_source_state", "État de la source", ["source"])

# --- Normalisation ---
NORMALIZED = Counter("cti_normalized_total", "Messages normalisés", ["result"])  # ok | dlq

# --- Déduplication ---
DEDUP = Counter("cti_dedup_total", "Résultat de déduplication", ["result"])
# unique | exact_duplicate | near_duplicate | error


def start_metrics_server(port: int) -> None:
    start_http_server(port)
