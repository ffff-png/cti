import os
import time
import random
import pickle
from datetime import datetime, timezone
from typing import Iterator

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from fake_useragent import UserAgent

from core.collector import Collector, HealthState, HealthStatus, RawRecord
from core.schema import SourceType


class FacebookCollector(Collector):
    """
    Collecteur Facebook via Chromium.
    Cible les pages publiques et groupes liés à la cybersécurité.
    """

    source_id = "facebook"
    source_type = SourceType.SOCIAL
    version = "1.0.0"

    DEFAULT_PAGES = ["CISAgov", "NCSC", "Mandiant", "CrowdStrike"]
    DEFAULT_GROUPS = ["CyberSecurityGroup", "EthicalHackingGroup"]

    def configure(self, config: dict) -> None:
        super().configure(config)
        self.pages = config.get("pages", self.DEFAULT_PAGES)
        self.groups = config.get("groups", self.DEFAULT_GROUPS)
        self.max_posts = int(config.get("max_posts", 15))
        self.delay_min = float(config.get("delay_min", 4.0))
        self.delay_max = float(config.get("delay_max", 8.0))
        self.headless = config.get("headless", True)
        self.manual_login = config.get("manual_login", False)

        self.email = config.get("facebook_email")
        self.password = config.get("facebook_password")
        self.cookies_file = config.get(
            "cookies_file", "cookies/facebook_cookies.pkl"
        )

        self._driver = None
        self._stopped = False
        self._failed = False
        self._collected = 0
        self._errors = 0

    def _get_random_delay(self) -> float:
        return random.uniform(self.delay_min, self.delay_max)

    def _setup_chromium(self) -> webdriver.Chrome:
        options = Options()
        if self.headless:
            options.add_argument("--headless=new")

        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument(f"--user-agent={UserAgent().random}")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")

        # Anti-détection avancée
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option("useAutomationExtension", False)

        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)

        # Cacher le webdriver au niveau JavaScript
        driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
            "source": """
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                })
            """
        })
        return driver

    def _save_cookies(self):
        os.makedirs(os.path.dirname(self.cookies_file), exist_ok=True)
        with open(self.cookies_file, 'wb') as f:
            pickle.dump(self._driver.get_cookies(), f)
        print("💾 Cookies Facebook sauvegardés")

    def _load_cookies(self) -> bool:
        if os.path.exists(self.cookies_file):
            print("📂 Chargement des cookies Facebook...")
            self._driver.get("https://www.facebook.com")
            time.sleep(2)
            with open(self.cookies_file, 'rb') as f:
                cookies = pickle.load(f)
                for cookie in cookies:
                    try:
                        self._driver.add_cookie(cookie)
                    except Exception:
                        pass
            self._driver.refresh()
            return True
        return False

    def _take_screenshot(self, name="debug"):
        screenshot_path = f"screenshot_fb_{name}_{int(time.time())}.png"
        self._driver.save_screenshot(screenshot_path)
        print(f"📸 Capture sauvegardée : {screenshot_path}")
        return screenshot_path

    def _login_to_facebook(self) -> bool:
        if not self.email or not self.password:
            print("⚠️  Identifiants Facebook manquants")
            return False

        try:
            print("🔗 Navigation vers facebook.com/login...")
            self._driver.get("https://www.facebook.com/login")
            time.sleep(4)

            self._take_screenshot("fb_login_page")

            # MODE LOGIN MANUEL
            if self.manual_login:
                print("\n" + "=" * 60)
                print("🔐 MODE LOGIN MANUEL ACTIVÉ (Facebook)")
                print("=" * 60)
                print("Connectez-vous manuellement dans la fenêtre Chromium.")
                print("Une fois connecté, revenez ici et appuyez sur Entrée...")
                input()
                print("✅ Login manuel détecté, sauvegarde des cookies...")
                self._save_cookies()
                return True

            # LOGIN AUTOMATIQUE
            print("🔑 Tentative de connexion automatique...")

            email_field = WebDriverWait(self._driver, 15).until(
                EC.presence_of_element_located(
                    (By.CSS_SELECTOR, 'input[type="email"]')
                )
            )
            email_field.clear()
            email_field.send_keys(self.email)

            password_field = self._driver.find_element(
                By.CSS_SELECTOR, 'input[type="password"]'
            )
            password_field.clear()
            password_field.send_keys(self.password)

            login_button = self._driver.find_element(
                By.CSS_SELECTOR, 'button[type="submit"]'
            )
            login_button.click()

            print("⏳ Attente de la redirection...")
            WebDriverWait(self._driver, 20).until(
                EC.url_contains("facebook.com/")
            )
            print("✅ Connexion Facebook réussie !")

            self._save_cookies()
            return True

        except Exception as e:
            print(f"❌ Échec connexion Facebook : {e}")
            self._take_screenshot("fb_login_error")
            return False

    def _extract_post(self, post_elem) -> dict | None:
        try:
            text_elems = post_elem.find_elements(
                By.CSS_SELECTOR, 'div[dir="auto"] span, span[dir="auto"]'
            )
            text = " ".join(
                [elem.text for elem in text_elems if elem.text.strip()]
            ).strip()

            if not text or len(text) < 15:
                return None

            author = "unknown"
            try:
                author = post_elem.find_element(
                    By.CSS_SELECTOR, 'strong span'
                ).text
            except Exception:
                pass

            timestamp = None
            try:
                timestamp = post_elem.find_element(
                    By.CSS_SELECTOR, 'abbr[data-utime]'
                ).get_attribute('data-utime')
            except Exception:
                pass

            return {
                'text': text,
                'author': author,
                'timestamp': timestamp
            }
        except Exception:
            return None

    def _collect_from_page(self, page_name: str) -> Iterator[RawRecord]:
        print(f"📄 Collecte page : {page_name}")
        self._driver.get(f"https://www.facebook.com/{page_name}/posts/")
        time.sleep(self._get_random_delay())

        count = 0
        while count < self.max_posts and not self._stopped:
            posts = self._driver.find_elements(
                By.CSS_SELECTOR,
                'div[role="article"], div[data-testid="post_container"]'
            )

            for post in posts[count:]:
                if count >= self.max_posts:
                    break
                data = self._extract_post(post)
                if data:
                    count += 1
                    self._collected += 1
                    yield RawRecord(
                        source_id=self.source_id,
                        source_type=self.source_type,
                        content=data['text'],
                        metadata={
                            'platform': 'facebook',
                            'page': page_name,
                            'author': data['author'],
                            'timestamp': data['timestamp']
                        }
                    )

            self._driver.execute_script(
                "window.scrollTo(0, document.body.scrollHeight);"
            )
            time.sleep(self._get_random_delay())

    def collect(self) -> Iterator[RawRecord]:
        self._failed = False
        self._collected = 0
        try:
            print("🚀 Initialisation de Chromium pour Facebook...")
            self._driver = self._setup_chromium()

            if not self._load_cookies():
                print("📴 Pas de cookies, tentative de connexion...")
                if not self._login_to_facebook():
                    self._failed = True
                    raise RuntimeError("Connexion à Facebook impossible.")

            for page in self.pages:
                if self._stopped:
                    break
                yield from self._collect_from_page(page)
                time.sleep(self._get_random_delay())

        except WebDriverException as e:
            self._failed = True
            raise e
        finally:
            if self._driver:
                self._driver.quit()

    def health(self) -> HealthStatus:
        if self._failed:
            return HealthStatus(
                HealthState.DOWN, "Collecteur Facebook en échec"
            )
        if self._errors > 0:
            return HealthStatus(
                HealthState.DEGRADED,
                f"{self._collected} posts, {self._errors} erreurs"
            )
        return HealthStatus(
            HealthState.OK, f"{self._collected} posts Facebook collectés"
        )

    def stop(self) -> None:
        self._stopped = True
        if self._driver:
            self._driver.quit()
