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
    "read_key" : "secrets.json",
    "transit_key": "aes256-key"
}

log_level        = logging.INFO

sm = SecretManager(secretcfg, log_level)
try:
    read_result = sm.execute(secretcfg.get("SOURCE"), "READ", sm, secretdef)
    if read_result.get("status") == "success":
        logger.info("Secrets retrieved successfully.")
    else:
        logger.error(f"Failed to retrieve secrets: {read_result.get('error', 'Unknown error')}")
    logger.info(f"Secrets:\n{json.dumps(read_result.get('data', {}), indent=4)}")
except Exception as e:
    logger.error(f"An error occurred: {e}")
result = sm.execute(secretcfg.get("SOURCE"), "LOGOUT", sm)