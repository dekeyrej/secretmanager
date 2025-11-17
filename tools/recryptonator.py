import json
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
import sys
import os


from secretmanager import SecretManager



secretcfg = {
    "SOURCE"         : "KUBEVAULT",
    "kube_config"    :  None,                       # or path to your kubeconfig file, e.g., "~/.kube/config"
    "service_account": "default",                   # Kubernetes service account for Vault authentication
    "namespace"      : "default",                   # Kubernetes namespace for service account
    "vault_url"      : "https://192.168.86.9:8200",
    "role"           : "demo",
    "ca_cert"        : True                         # or path to CA cert file
}

if os.getenv("VAULT_URL"):
    secretcfg["vault_url"] = os.getenv("VAULT_URL")
else:
    secretcfg["vault_url"] = "https://192.168.86.9:8200"

secretdef = {
    "read_type"  : "SECRET",
    "secret_name": "matrix-secrets",
    "namespace"  : "default",
    "read_key"   : "secrets.json",
    "transit_key": "aes256-key"
}

log_level        = logging.INFO
validate         = True  # Set to True if you want to validate the secrets after re-encryption, otherwise False


logging.info("🔥 Recryptonator initializing… preparing for vault key rotation! 🔥")
logging.debug("SecretManager initializing.")
sm = SecretManager(secretcfg, log_level)
logging.debug("Reading Kubernetes secret/ciphertext and decrypting with current vault transit key.")
read_status = sm.execute(secretcfg.get("SOURCE"), "READ", sm, secretdef)
if read_status['status'] != "success":
    logging.error(f"Failed to read secret: {read_status.get('error', 'Unknown error')}")
    sys.exit(1)
decrypted_data = read_status['data']
logging.debug("Rotating vault key.")
rstatus = sm.execute(secretcfg.get("SOURCE"), "ROTATE", sm, secretdef.get("transit_key"))
if rstatus['status'] != "success":
    logging.error("Failed to rotate the Vault key.")
    sys.exit(1)
logging.debug("Re-encrypting data with new vault key, and updating Kubernetes secret with new ciphertext.")
status = sm.execute(secretcfg.get("SOURCE"), "CREATE", sm, secretdef, json.dumps(decrypted_data))['status']
if status != "success":
    logging.error("Failed to re-encrypt the secret with the new Vault key.")
    sys.exit(1)
logging.info(f"Secret {secretdef['secret_name']} in namespace {secretdef['namespace']} has been re-encrypted with the new Vault key.")
if validate:
    new_decrypted_data = sm.execute(secretcfg.get("SOURCE"), "READ", sm, secretdef)['data']

    if decrypted_data != new_decrypted_data:
        logging.error("Validation failed: Secrets do not match.")
        raise ValueError("Validation failed: Secrets do not match.")
    else:
        logging.info("Validation successful: Secrets match.")
result = sm.execute(secretcfg.get("SOURCE"), "LOGOUT", sm)