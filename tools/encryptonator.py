import argparse
import json
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
import sys

from secretmanager import SecretManager

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


secretcfg = {
    "SOURCE"         : "KUBEVAULT",
    "kube_config"    : None,                        # or path to your kubeconfig file, e.g., "~/.kube/config"
    "service_account": "default",                   # Kubernetes service account for Vault authentication
    "namespace"      : "default",                   # Kubernetes namespace for service account
    "vault_url"      : "https://192.168.86.9:8200",
    "role"           : "demo",
    "ca_cert"        : True                         # True if certifi's PEM file has been patched
}

secretdef = {
    "read_type"  : "SECRET",
    "secret_name": "matrix-secrets",
    "namespace"  : "default",
    "read_key" : "secrets.json",
    "transit_key": "aes256-key"
}

log_level        = logging.INFO
validate         =  True

sm = SecretManager(secretcfg, log_level)
sm.execute(secretcfg.get("SOURCE"), "CREATE", sm, secretdef, secrettext)

if validate:
    read_result = sm.execute(secretcfg.get("SOURCE"), "READ", sm, secretdef)

    if secrets != read_result.get("data", {}):
        logging.error("Validation failed: secrets do not match.")
        raise ValueError("Validation failed: secrets do not match.")
    else:
        logging.info("Validation successful: secrets match.")
result = sm.execute(secretcfg.get("SOURCE"), "LOGOUT", sm)