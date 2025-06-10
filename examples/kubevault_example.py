import json
import logging
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../secretmanager')))

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

log_level        = "INFO"

sm = SecretManager(secretcfg, log_level)
secrets = sm.read_secrets(secretdef.get("secret_name"), secretdef.get("namespace"), 
                                 secretdef.get("read_type"),   secretdef.get("secret_key"), 
                                 secretdef.get("transit_key"))
logging.info(f"Secrets:\n{json.dumps(secrets, indent=4)}")