from secretmanager.secretregistry import SECRET_VERB_REGISTRY
from secretmanager.manager import SecretManager
import pytest
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

test_tuples = [("ENVIRONMENT", "ROTATE")]

for source in SECRET_VERB_REGISTRY.keys():
    for verb in SECRET_VERB_REGISTRY[source].keys():
        test_tuples.append((source, verb))

sm = SecretManager()


@pytest.mark.parametrize("source, verb", test_tuples)
def test_execute_valid(source, verb):
    result = sm.execute(source, verb, sm)
    assert result is not None
