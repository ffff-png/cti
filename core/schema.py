import json
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from uuid import uuid4

import stix2
from pydantic import BaseModel, Field


class SourceType(str, Enum):
    SITE = "site"
    SOCIAL = "social"
    API = "api"
    DARKWEB = "darkweb"


class TLP(str, Enum):
    CLEAR = "CLEAR"
    GREEN = "GREEN"
    AMBER = "AMBER"
    AMBER_STRICT = "AMBER+STRICT"
    RED = "RED"


class Envelope(BaseModel):
    record_id: str = Field(default_factory=lambda: str(uuid4()))
    source_id: str
    source_type: SourceType
    collector_version: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content_hash: str
    tlp: TLP = TLP.AMBER
    reliability: str = Field(pattern="^[A-F]$")
    raw_ref: str | None = None


class PivotRecord(BaseModel):
    envelope: Envelope
    payload: dict  # objet STIX 2.1 sérialisé


def compute_hash(canonical_text: str) -> str:
    """Empreinte du texte normalisé (minuscules, espaces nettoyés)."""
    norm = " ".join(canonical_text.lower().split())
    return "sha256:" + sha256(norm.encode("utf-8")).hexdigest()


def make_record(source_id, source_type, canonical_text, stix_obj,
                reliability="C", tlp=TLP.AMBER,
                collector_version="0.1.0", raw_ref=None) -> PivotRecord:
    env = Envelope(
        source_id=source_id,
        source_type=source_type,
        collector_version=collector_version,
        content_hash=compute_hash(canonical_text),
        tlp=tlp,
        reliability=reliability,
        raw_ref=raw_ref,
    )
    return PivotRecord(envelope=env, payload=json.loads(stix_obj.serialize()))


def validate_record(data: dict) -> PivotRecord:
    """Rejette tout message dont l'enveloppe ou l'objet STIX est invalide."""
    rec = PivotRecord.model_validate(data)
    stix2.parse(rec.payload, allow_custom=False)
    return rec
