from collectors.failing import FailingCollector
from collectors.abusech import ThreatFoxCollector, URLhausCollector
from collectors.fake import FakeCollector
from collectors.misp import MISPCollector
from collectors.onion import OnionCollector
from collectors.otx import OTXCollector
from collectors.site import SiteCollector
from collectors.x import XCollector

# type indiqué dans sources.yml -> classe du collecteur
REGISTRY = {
    "fake": FakeCollector,
    "failing": FailingCollector,
    "misp": MISPCollector,
    "onion": OnionCollector,
    "otx": OTXCollector,
    "site": SiteCollector,
    "threatfox": ThreatFoxCollector,
    "urlhaus": URLhausCollector,
    "x": XCollector,
}
