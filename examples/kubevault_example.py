import json
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

from secretmanager import SecretManager

secretcfg = {
    "SOURCE": "KUBEVAULT",
    "kube_config": None,
    "service_account": "default",
    "namespace" : "default",
    "vault_url": "https://192.168.86.9:8200",
    "role": "demo",
    "ca_cert": True
}

secretdef = {
    "read_type"  : "SECRET",
    "secret_name": "matrix-secrets",
    "namespace"  : "default",
    "secret_key" : "secrets.json",
    "transit_key": "aes256-key"
}

log_level        = logging.INFO

sm = SecretManager(secretcfg, log_level)  #, or
# sm = SecretManager()
# sm.configure_secret_type(secretcfg)
secrets = sm.read_secrets(secretdef)
logger.info(f"Secrets:\n{json.dumps(secrets, indent=4)}")
sm.logout_vault()