import json
import logging
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../secretmanager')))

from secretmanager import SecretManager

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

config = {
    "SOURCE"         : "KUBEVAULT",
    "kube_config"    :  None,                       # or path to your kubeconfig file, e.g., "~/.kube/config"
    "service_account": "default",                   # Kubernetes service account for Vault authentication
    "namespace"      : "default",                   # Kubernetes namespace for service account
    "vault_url"      : "https://192.168.86.9:8200",
    "role"           : "demo",
    "ca_cert"        : True                         # or path to CA cert file
}

log_level        = "INFO"

namespace        = "default"
secret_name      = "matrix-secrets"
read_type        = "SECRET"                          # Type of secret to read from Kubernetes
secret_data_name = "secrets.json"
transit_key      = "aes256-key"

validate         = True  # Set to True if you want to validate the secrets after re-encryption, otherwise False

logging.info("🔥 Recryptonator initializing… preparing for vault key rotation! 🔥")
logging.debug("SecretManager initializing.")
sm = SecretManager(config, log_level)
logging.debug("Reading Kubernetes secret/ciphertext and decrypting with current vault transit key.")
decrypted_data = sm.read_secrets(secret_name, namespace, read_type, secret_data_name, transit_key)
logging.debug("Rotating vault key.")
sm.rotate_vault_key(transit_key)
logging.debug("Re-encrypting data with new vault key.")
ciphertext = sm.encrypt_data_with_vault(transit_key, json.dumps(decrypted_data))
logging.debug("Updating Kubernetes secret with new ciphertext.")
sm.create_k8s_secret(namespace, secret_name, secret_data_name, ciphertext)
logging.info(f"Secret {secret_name} in namespace {namespace} has been re-encrypted with the new Vault key.")
if validate:
    new_decrypted_data = sm.read_secrets(secret_name, namespace, read_type, secret_data_name, transit_key)

    if decrypted_data != new_decrypted_data:
        logging.error("Validation failed: Secrets do not match.")
        raise ValueError("Validation failed: Secrets do not match.")
    else:
        logging.info("Validation successful: Secrets match.")