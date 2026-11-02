"""État persistant d'une source (curseur, cookies de session, articles déjà lus).
L'orchestrateur recrée le collecteur à chaque collecte : tout ce qui doit survivre
d'une collecte à l'autre est écrit ici, dans state/<source>.json (droits 600)."""
import json
import os
import re
from pathlib import Path

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "state"


class StateStore:
    def __init__(self, source_id: str, base_dir: str | None = None):
        base = Path(base_dir or os.environ.get("CTI_STATE_DIR") or DEFAULT_DIR)
        base.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", source_id)
        self.path = base / f"{safe}.json"

    def load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, ValueError):
            return {}

    def save(self, data: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)                      # contient des cookies de session
        os.replace(tmp, self.path)
