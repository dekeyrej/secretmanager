import json
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
import sys
import os

from secretmanager import SecretManager

with open("secretcfg.json") as f:
    secretcfg = json.loads(f.read())

with open("secretdef.json") as f:
    secretdef = json.loads(f.read())

log_level        = logging.INFO
validate         = os.getenv("VALIDATE", "True").lower() in ("true", "1", "yes")  # Set to True if you want to validate the secrets after re-encryption, otherwise False

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