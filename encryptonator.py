import argparse
import hashlib
import logging
from secretmanager import SecretManager

def hash_data(data):
    """Generates a SHA-256 hash of the input data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def parse_args():
    parser = argparse.ArgumentParser(description="Encrypt secrets and store them in Kubernetes using Vault.")
    parser.add_argument('--url', default="https://192.168.86.60:8200", help="URL of your Vault server (default: https://192.168.86.60:8200)")
    parser.add_argument('--cert', default="ca.crt", help="Path to your CA certificate file (default: ca.crt)")
    parser.add_argument('--role', default="demo", help="Vault role for Kubernetes authentication")
    parser.add_argument('--account', default="default", help="Kubernetes service account for Vault authentication (default: default)")
    parser.add_argument('--path', default="secrets.json", help="Path to your secrets file")
    parser.add_argument('--keyname', default="aes256-key", help="Vault transit key for encryption")
    parser.add_argument('--ns', default="default", help="Kubernetes namespace where the secret will be created (default: default)")
    parser.add_argument('--secretname', default="matrix-secrets", help="Name of the Kubernetes secret to create")
    parser.add_argument('--dataname', default="secrets.json", help="Name of the data field in the Kubernetes secret")
    parser.add_argument('--v', dest='validate', action='store_true', help="Whether to validate the secrets file (default: False)")
    return parser.parse_args()

args = parse_args()
vault_url        = args.url
ca_cert          = args.cert
role             = args.role
service_account  = args.account
file_path        = args.path
transit_key      = args.keyname
namespace        = args.ns
secret_name      = args.secretname
secret_data_name = args.dataname
validate         = args.validate

sm = SecretManager(vault_url, service_account, role, ca_cert)

secrets = sm.read_data_from_file(file_path)
ciphertext = sm.encrypt_data_with_vault(transit_key, secrets)
sm.create_k8s_secret(namespace, secret_name, secret_data_name, ciphertext)

if validate:
    original_hash = hash_data(secrets)
    k8s_enc_secret = sm.read_namespaced_secret(namespace, secret_name, secret_data_name)
    decrypted_data = sm.decrypt_data_with_vault(transit_key, k8s_enc_secret)
    decrypted_hash = hash_data(decrypted_data)

    if original_hash != decrypted_hash:
        logging.error("Validation failed: Hashes do not match.")
        raise ValueError("Validation failed: Hashes do not match.")
    else:
        logging.info("Validation successful: Hashes match.")
