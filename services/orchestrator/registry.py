from collectors.failing import FailingCollector
from collectors.fake import FakeCollector

# type indiqué dans sources.yml -> classe du collecteur
REGISTRY = {
    "fake": FakeCollector,
    "failing": FailingCollector,
}
