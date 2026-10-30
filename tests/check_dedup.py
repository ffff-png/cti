import redis
from simhash import Simhash

from services.deduplicator.main import Deduplicator, hamming

r = redis.Redis(db=15, decode_responses=True)
r.flushdb()
d = Deduplicator(r, ttl=60)


def rec(rid, h, desc):
    return {"envelope": {"record_id": rid, "content_hash": h},
            "payload": {"description": desc}}


# --- Niveau 1 : doublon exact ---
a = rec("r1", "sha256:aaa", "IP suspecte 203.0.113.60")
print("1er message        :", d.classify(a)[0]); d.register(a)
b = rec("r2", "sha256:aaa", "Autre phrase, même indicateur")
print("même empreinte     :", d.classify(b))

# --- Niveau 2 : quasi-doublon (textes longs) ---
BASE = (
    "Rapport d'analyse : une campagne d'hameçonnage cible les employés d'institutions "
    "publiques. Les messages imitent des notifications administratives et redirigent vers "
    "un faux portail d'authentification. Les analystes recommandent de bloquer les domaines "
    "associés, de vérifier les journaux de la passerelle de messagerie et de sensibiliser "
    "les utilisateurs aux signes d'un message frauduleux. L'infrastructure utilise des "
    "services d'hébergement temporaires et change de domaine toutes les quelques heures, "
    "ce qui complique le blocage durable. Aucune adresse réelle n'est citée dans cet "
    "exemple de test."
)
VARIANT = BASE.replace("quelques heures", "quelques jours")
OTHER = ("Note de veille : une nouvelle version d'un outil de supervision réseau a été "
         "publiée avec des correctifs de stabilité, une meilleure gestion des journaux, "
         "une interface remaniée et la prise en charge de nouveaux protocoles de collecte. "
         "Les administrateurs sont invités à planifier la mise à jour pendant une fenêtre "
         "de maintenance et à conserver une sauvegarde de la configuration existante "
         "avant toute opération sur les serveurs de production concernés.")

c1 = rec("r3", "sha256:c1", BASE)
print("texte long original:", d.classify(c1)[0]); d.register(c1)

dist = hamming(Simhash(BASE).value, Simhash(VARIANT).value)
status, info = d.classify(rec("r4", "sha256:c2", VARIANT))
print(f"variante (distance {dist}) :", status, info)
assert status == ("near" if dist <= 3 else "unique"), "incohérence"

status, info = d.classify(rec("r5", "sha256:c3", OTHER))
print("texte différent    :", status)
assert status == "unique"

r.flushdb()
print("Tests de logique : OK")
