from collectors.failing import FailingCollector
from collectors.fake import FakeCollector
from collectors.otx import OTXCollector

# type indiqué dans sources.yml -> classe du collecteur
REGISTRY = {
    "fake": FakeCollector,
    "failing": FailingCollector,
    "otx": OTXCollector,
}
