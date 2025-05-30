import hashlib
import logging
import os
from secretmanager import SecretManager

vault_url        = os.getenv("VAULT_URL", "https://192.168.86.60:8200")
ca_cert          = os.getenv("CA_CERT", "ca.crt")
role             = os.getenv("ROLE", "demo")
service_account  = os.getenv("SERVICE_ACCOUNT", "default")
transit_key      = os.getenv("TRANSIT_KEY", "aes256-key")
namespace        = os.getenv("NAMESPACE", "default")
secret_name      = os.getenv("SECRET_NAME", "matrix-secrets7")
secret_data_name = os.getenv("SECRET_DATA_NAME", "secrets.json")
validate         = os.getenv("VALIDATE", "1")  # Set to True if you want to validate the secrets file

def hash_data(data):
    """Generates a SHA-256 hash of the input data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

sm = SecretManager(vault_url, service_account, role, ca_cert)

k8s_old_secret = sm.read_namespaced_secret(namespace, secret_name, secret_data_name)
decrypted_data = sm.decrypt_data_with_vault(transit_key, k8s_old_secret)
sm.rotate_vault_key(transit_key)
ciphertext = sm.encrypt_data_with_vault(transit_key, decrypted_data)
sm.create_k8s_secret(namespace, secret_name, secret_data_name, ciphertext)
logging.info(f"Secret {secret_name} in namespace {namespace} has been re-encrypted with the new Vault key.")

if validate == "1":
    original_hash = hash_data(decrypted_data)
    k8s_enc_secret = sm.read_namespaced_secret(namespace, secret_name, secret_data_name)
    new_decrypted_data = sm.decrypt_data_with_vault(transit_key, k8s_enc_secret)
    new_hash = hash_data(new_decrypted_data)

    if original_hash != new_hash:
        logging.error("Validation failed: Hashes do not match.")
        raise ValueError("Validation failed: Hashes do not match.")
    else:
        logging.info("Validation successful: Hashes match.")