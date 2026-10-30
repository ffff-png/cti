import argparse
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import yaml
from apscheduler.schedulers.background import BackgroundScheduler

from core.collector import HealthState
from core.kafka_io import KafkaPublisher
from core.metrics import (COLLECT_DURATION, COLLECTED, COLLECTIONS,
                          SOURCE_STATE, start_metrics_server)
from services.orchestrator.registry import REGISTRY

METRICS_TOPIC = "ops.metrics"
STATE_VALUE = {"NEW": 0, "OK": 0, "DEGRADED": 1, "SUSPENDED": 2, "DISABLED": 3}
_DURATION_RE = re.compile(r"^(\d+)([smh])$")


def parse_duration(text) -> int:
    m = _DURATION_RE.match(str(text).strip())
    if not m:
        raise ValueError(f"durée invalide : {text!r} (exemples : 30s, 15m, 2h)")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


@dataclass
class SourceState:
    id: str
    type: str
    every_s: int
    params: dict
    max_failures: int
    cooldown_s: int
    enabled: bool = True
    state: str = "NEW"
    consecutive_failures: int = 0
    total_runs: int = 0
    total_records: int = 0
    total_failures: int = 0
    last_run: str = ""
    last_error: str = ""
    suspended_until: float = 0.0


class Orchestrator:
    def __init__(self, config: dict, publisher):
        self.pub = publisher
        self.sources: dict[str, SourceState] = {}
        defaults = config.get("defaults", {})
        for s in config.get("sources", []):
            if s["id"] in self.sources:
                raise ValueError(f"identifiant dupliqué : {s['id']}")
            if s["type"] not in REGISTRY:
                raise ValueError(f"type inconnu pour {s['id']} : {s['type']}")
            enabled = s.get("enabled", True)
            self.sources[s["id"]] = SourceState(
                id=s["id"],
                type=s["type"],
                every_s=parse_duration(s["every"]),
                params=s.get("params") or {},
                max_failures=int(s.get("max_failures", defaults.get("max_failures", 3))),
                cooldown_s=parse_duration(s.get("cooldown", defaults.get("cooldown", "60s"))),
                enabled=enabled,
                state="NEW" if enabled else "DISABLED",
            )
            self._publish_state(self.sources[s["id"]])

    @staticmethod
    def _publish_state(st: SourceState) -> None:
        SOURCE_STATE.labels(source=st.id).set(STATE_VALUE.get(st.state, 0))

    # --- une collecte pour une source ---
    def run_source(self, st: SourceState) -> None:
        if not st.enabled:
            return
        if time.time() < st.suspended_until:
            return                       # suspendue : on ne fait rien

        started = time.time()
        records = 0
        ok = True
        collector = REGISTRY[st.type]()
        collector.source_id = st.id      # identifiant de la configuration
        try:
            collector.configure(dict(st.params))
            topic = f"raw.{st.id}"
            for rec in collector.collect():
                self.pub.publish(topic, key=st.id, value=rec.to_dict())
                records += 1
            self.pub.flush()
            health = collector.health()
            if health.state == HealthState.DOWN:
                raise RuntimeError(f"collecteur en panne : {health.detail}")
            self._on_success(st, records, degraded=health.state == HealthState.DEGRADED)
        except Exception as exc:
            ok = False
            self._on_failure(st, exc)
        finally:
            collector.stop()
            duration = time.time() - started
            COLLECT_DURATION.labels(source=st.id).observe(duration)
            COLLECTIONS.labels(source=st.id, status="ok" if ok else "error").inc()
            COLLECTED.labels(source=st.id).inc(records)
            self._publish_state(st)
            self.pub.publish(METRICS_TOPIC, key=st.id, value={
                "source_id": st.id,
                "event": "run",
                "ok": ok,
                "records": records,
                "duration_s": round(time.time() - started, 3),
                "state": st.state,
                "ts": datetime.now(timezone.utc).isoformat(),
            })
            self.pub.flush()

    @staticmethod
    def _stamp(st: SourceState) -> None:
        st.total_runs += 1
        st.last_run = datetime.now().strftime("%H:%M:%S")

    def _on_success(self, st, records, degraded=False):
        self._stamp(st)
        st.total_records += records
        st.consecutive_failures = 0
        st.last_error = ""
        st.suspended_until = 0.0
        st.state = "DEGRADED" if degraded else "OK"

    def _on_failure(self, st, exc):
        self._stamp(st)
        st.total_failures += 1
        st.consecutive_failures += 1
        st.last_error = f"{type(exc).__name__}: {exc}"
        if st.consecutive_failures >= st.max_failures:
            # le compteur n'est pas remis à zéro : après le repos, un seul
            # nouvel échec suffit à suspendre de nouveau (état semi-ouvert)
            st.state = "SUSPENDED"
            st.suspended_until = time.time() + st.cooldown_s
        else:
            st.state = "DEGRADED"

    # --- affichage ---
    def status_table(self) -> str:
        lines = [f"{'SOURCE':<12}{'ÉTAT':<11}{'RUNS':>5}{'ENREG.':>8}{'ÉCHECS':>8}  "
                 f"{'DERNIER':<9} DÉTAIL"]
        now = time.time()
        for st in self.sources.values():
            detail = st.last_error
            if st.state == "SUSPENDED":
                detail = f"reprise dans {max(0, int(st.suspended_until - now))} s | {detail}"
            lines.append(f"{st.id:<12}{st.state:<11}{st.total_runs:>5}{st.total_records:>8}"
                         f"{st.total_failures:>8}  {st.last_run or '-':<9} {detail}")
        return "\n".join(lines)

    # --- planification ---
    def start(self) -> BackgroundScheduler:
        scheduler = BackgroundScheduler()
        for st in self.sources.values():
            if not st.enabled:
                continue
            scheduler.add_job(
                self.run_source, "interval", seconds=st.every_s, args=[st],
                id=st.id, max_instances=1, coalesce=True,
                next_run_time=datetime.now(timezone.utc),   # première collecte immédiate
            )
        scheduler.start()
        return scheduler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/sources.yml")
    ap.add_argument("--bootstrap", default="localhost:9092")
    ap.add_argument("--duration", type=int, default=0,
                    help="durée en secondes (0 = jusqu'à Ctrl+C)")
    ap.add_argument("--status-every", type=int, default=15)
    ap.add_argument("--metrics-port", type=int, default=8001)
    args = ap.parse_args()
    start_metrics_server(args.metrics_port)

    orch = Orchestrator(load_config(args.config), KafkaPublisher(args.bootstrap))
    scheduler = orch.start()
    print(f"Orchestrateur démarré : {len(orch.sources)} source(s). Ctrl+C pour arrêter.\n")

    t0 = time.time()
    try:
        while args.duration == 0 or time.time() - t0 < args.duration:
            time.sleep(args.status_every)
            print(f"--- t = {int(time.time() - t0)} s ---")
            print(orch.status_table(), "\n")
    except KeyboardInterrupt:
        pass
    finally:
        scheduler.shutdown(wait=True)
        orch.pub.flush()
        print("\nÉtat final :")
        print(orch.status_table())


if __name__ == "__main__":
    main()
