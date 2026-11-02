
import asyncio
import logging
import random
import time
from pathlib import Path
from typing import Iterator

from twscrape import API, gather
from twscrape.logger import set_log_level

from core.collector import Collector, HealthState, HealthStatus, RawRecord
from core.ioc import extract_iocs
from core.schema import SourceType
from core.state import StateStore


logger = logging.getLogger(__name__)
set_log_level("ERROR")


class XCollector(Collector):
    """Collecteur CTI X via twscrape."""

    source_id = "x"
    source_type = SourceType.SOCIAL
    version = "1.0.0"

    DEFAULT_KEYWORDS = [
        "cyberattack",
        "ransomware",
        "malware",
        "phishing",
        "data breach",
        "zero-day",
        "APT",
        "CVE-",
    ]

    DEFAULT_PROFILES = [
        "CISAgov",
        "NCSC",
        "mandiant",
        "CrowdStrike",
        "TheHackerNews",
    ]

    MAX_SEEN_IDS = 10000

    def configure(self, config: dict) -> None:
        super().configure(config)

        self.keywords = config.get("keywords", self.DEFAULT_KEYWORDS)
        self.profiles = config.get("profiles", self.DEFAULT_PROFILES)

        self.max_posts = int(config.get("max_posts", 15))
        self.delay_min = float(config.get("delay_min", 1))
        self.delay_max = float(config.get("delay_max", 3))

        if self.max_posts < 1:
            raise ValueError("max_posts doit être supérieur à zéro")

        if self.delay_min < 0 or self.delay_max < self.delay_min:
            raise ValueError("Intervalle delay_min/delay_max invalide")

        # Résolution du chemin depuis la racine du projet.
        project_root = Path(__file__).resolve().parent.parent

        db_path = Path(config.get("accounts_db", "data/x_accounts.db"))

        if not db_path.is_absolute():
            db_path = project_root / db_path

        self.db_path = db_path

        # État persistant entre les exécutions.
        self.state_store = StateStore(self.source_id)
        saved_state = self.state_store.load()

        self.seen_ids = set(saved_state.get("seen_ids", []))

        self.api = None
        self.stopped = False

        self.successful_queries = 0
        self.failed_queries = 0
        self.collected_records = 0
        self.collected_tweets = 0
        self.errors = []

    def _build_queries(self) -> list[str]:
        """Construit les recherches par mots-clés et par profils."""

        queries = []

        for keyword in self.keywords:
            keyword = str(keyword).strip()
            if keyword:
                queries.append(keyword)

        for profile in self.profiles:
            username = str(profile).strip().lstrip("@")

            if username and username.replace("_", "").isalnum():
                queries.append(f"from:{username}")

        return list(dict.fromkeys(queries))

    def _initialize_api(self) -> None:
        if not self.db_path.is_file():
            raise FileNotFoundError(
                f"Base twscrape introuvable : {self.db_path}"
            )

        self.api = API(str(self.db_path))

        logger.info("Base twscrape chargée : %s", self.db_path)

    def _save_state(self) -> None:
        self.state_store.save({
            "seen_ids": list(self.seen_ids)[-self.MAX_SEEN_IDS:]
        })

    def _search(self, query: str) -> list:
        """Exécute une recherche twscrape."""

        async def fetch():
            return await gather(
                self.api.search(query, limit=self.max_posts)
            )

        return asyncio.run(fetch())

    def _collect_query(self, query: str) -> Iterator[RawRecord]:
        """Collecte les tweets d'une recherche et extrait les IOC."""

        tweets = self._search(query)

        self.successful_queries += 1

        logger.info(
            "Recherche réussie : %s (%d tweets)",
            query,
            len(tweets),
        )

        for tweet in tweets:

            if self.stopped:
                break

            tweet_id = str(tweet.id)

            if tweet_id in self.seen_ids:
                continue

            text = tweet.rawContent or ""

            user = tweet.user
            username = user.username if user else "unknown"

            tweet_url = (
                f"https://x.com/{username}/status/{tweet_id}"
                if username != "unknown"
                else None
            )

            iocs = extract_iocs(text)

            self.collected_tweets += 1

            for ioc_type, ioc_value in iocs:

                if self.stopped:
                    break

                record = RawRecord(
                    source_id=self.source_id,
                    source_type=self.source_type,
                    content=ioc_value,
                    metadata={
                        "platform": "x",
                        "tweet_id": tweet_id,
                        "ioc_type": ioc_type,
                        "query": query,
                        "author": username,
                        "url": tweet_url,
                        "timestamp": (
                            tweet.date.isoformat()
                            if tweet.date else None
                        ),
                        "likes": tweet.likeCount,
                        "retweets": tweet.retweetCount,
                        "replies": tweet.replyCount,
                        "language": tweet.lang,
                    },
                )

                self.collected_records += 1
                yield record

            # Enregistré après traitement du tweet.
            self.seen_ids.add(tweet_id)
            self._save_state()

            time.sleep(random.uniform(
                self.delay_min,
                self.delay_max,
            ))

    def collect(self) -> Iterator[RawRecord]:
        """Point d'entrée appelé par l'orchestrateur."""

        self.successful_queries = 0
        self.failed_queries = 0
        self.collected_records = 0
        self.collected_tweets = 0
        self.errors = []

        self.stopped = False

        self._initialize_api()

        queries = self._build_queries()

        if not queries:
            raise RuntimeError("Aucune recherche X configurée")

        logger.info("Début de collecte X : %d recherches", len(queries))

        for query in queries:

            if self.stopped:
                break

            try:
                yield from self._collect_query(query)

            except Exception as exc:
                self.failed_queries += 1
                self.errors.append(f"{query}: {exc}")

                logger.exception(
                    "Échec de la recherche X : %s",
                    query,
                )

        # Une panne totale doit remonter à l'orchestrateur.
        if self.failed_queries > 0 and self.successful_queries == 0:
            raise RuntimeError(
                "Toutes les recherches X ont échoué : "
                + "; ".join(self.errors)
            )

        logger.info(
            "Collecte terminée : %d tweets, %d IOC, "
            "%d recherches réussies, %d échouées",
            self.collected_tweets,
            self.collected_records,
            self.successful_queries,
            self.failed_queries,
        )

    def health(self) -> HealthStatus:

        if self.failed_queries > 0 and self.successful_queries == 0:
            return HealthStatus(
                HealthState.DOWN,
                "Toutes les recherches X ont échoué",
            )

        if self.failed_queries > 0:
            return HealthStatus(
                HealthState.DEGRADED,
                f"{self.successful_queries} recherches réussies, "
                f"{self.failed_queries} échouées",
            )

        return HealthStatus(
            HealthState.OK,
            f"{self.collected_records} IOC collectés",
        )

    def stop(self) -> None:
        self.stopped = True
        logger.info("Arrêt du collecteur X demandé")

