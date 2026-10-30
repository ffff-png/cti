from services.orchestrator.main import Orchestrator, parse_duration


class DummyPublisher:
    def __init__(self):
        self.messages = []

    def publish(self, topic, key, value):
        self.messages.append((topic, value))

    def flush(self):
        pass


config = {
    "defaults": {"max_failures": 3, "cooldown": "60s"},
    "sources": [
        {"id": "fake", "type": "fake", "every": "20s", "params": {"count": 5}},
        {"id": "bad", "type": "failing", "every": "10s"},
        {"id": "off", "type": "fake", "every": "1m", "enabled": False},
    ],
}
pub = DummyPublisher()
orch = Orchestrator(config, pub)

print("durées :", parse_duration("30s"), parse_duration("15m"), parse_duration("2h"))

# 1. Source saine
orch.run_source(orch.sources["fake"])
raw = [m for m in pub.messages if m[0] == "raw.fake"]
print("fake :", orch.sources["fake"].state, "|", len(raw), "enregistrements")
assert orch.sources["fake"].state == "OK" and len(raw) == 5

# 2. Source qui échoue : DEGRADED, DEGRADED, puis SUSPENDED
bad = orch.sources["bad"]
for i in range(3):
    orch.run_source(bad)
    print(f"bad, échec {i + 1} :", bad.state)
assert bad.state == "SUSPENDED"

# 3. Pendant la suspension, la source n'est pas relancée
runs = bad.total_runs
orch.run_source(bad)
assert bad.total_runs == runs
print("suspendue : aucune collecte lancée")

# 4. Fin du repos : un seul échec suffit à re-suspendre
bad.suspended_until = 0
orch.run_source(bad)
print("après repos, nouvel échec :", bad.state)
assert bad.state == "SUSPENDED" and bad.total_runs == runs + 1

# 5. Source désactivée
orch.run_source(orch.sources["off"])
assert orch.sources["off"].total_runs == 0
print("source désactivée : ignorée")

print("\n" + orch.status_table())
print("\nTests de logique : OK")
