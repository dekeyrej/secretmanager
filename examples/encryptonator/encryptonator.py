import argparse
import json
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../secretmanager')))

from secretmanager import SecretManager

config = {
    "SOURCE"         : "KUBEVAULT",
    "kube_config"    : None,                        # or path to your kubeconfig file, e.g., "~/.kube/config"
    "service_account": "default",                   # Kubernetes service account for Vault authentication
    "namespace"      : "default",                   # Kubernetes namespace for service account
    "vault_url"      : "https://192.168.86.9:8200",
    "role"           : "demo",
    "ca_cert"        : "ca.crt"                     # or True if certifi's PEM file has been patched
}

log_level        = "INFO"
file_path        = "/tmp/encryptonator/secrets.json"  # "/tmp/encryptonator/sample_secrets.json"
transit_key      = "aes256-key"
namespace        = "default"
secret_name      = "matrix-secrets"
read_type        = "SECRET"  # Type of secret to read from Kubernetes
secret_data_name = "secrets.json"
validate         =  True

sm = SecretManager(config, log_level)

parser = argparse.ArgumentParser()
parser.add_argument('--json', help='JSON string to encrypt')
parser.add_argument('--file', help='Path to JSON file')
args = parser.parse_args()

if args.json:
    secrettext = args.json
elif args.file:
    with open(args.file, 'r') as f:
        secrettext = f.read()
else:
    logging.error("No input source specified.")
    sys.exit(1)

try:
    secrets = json.loads(secrettext)
except json.JSONDecodeError as e:
    logging.error(f"Invalid JSON input: {e}")
    sys.exit(1)

ciphertext = sm.encrypt_data_with_vault(transit_key, secrettext)
sm.create_k8s_secret(namespace, secret_name, secret_data_name, ciphertext)

if validate:
    read_secrets = sm.read_secrets(secret_name, namespace, read_type, secret_data_name, transit_key)

    if secrets != read_secrets:
        logging.error("Validation failed: secrets do not match.")
        raise ValueError("Validation failed: secrets do not match.")
    else:
        logging.info("Validation successful: secrets match.")
