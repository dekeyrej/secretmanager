import os
import sys
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../secretmanager')))

from secretmanager import SecretManager

config = {
    "SOURCE": "KUBEVAULT",
    "kube_config": None,                       # or path to your kubeconfig file, e.g., "~/.kube/config"
    "service_account": "default",              # Kubernetes service account for Vault authentication
    "namespace" : "default",                   # Kubernetes namespace for service account
    "vault_url": "https://192.168.86.9:8200",
    "role": "demo",
    "ca_cert": True                            # or path to CA cert file
}

log_level        = "INFO"

file_path        = "examples/encryptonator/secrets.json"  # "examples/encryptonator/sample_secrets.json"
transit_key      = "aes256-key"
namespace        = "default"
secret_name      = "matrix-secrets"
read_type        = "SECRET"  # Type of secret to read from Kubernetes
secret_data_name = "secrets.json"
validate         =  True

sm = SecretManager(config, log_level)

secrettext = sm.read_data_from_file(file_path)
ciphertext = sm.encrypt_data_with_vault(transit_key, secrettext)
sm.create_k8s_secret(namespace, secret_name, secret_data_name, ciphertext)

if validate:
    secrets = sm.load_json_secrets(secrettext)
    read_secrets = sm.read_secrets(secret_name, namespace, read_type, secret_data_name, transit_key)

    if secrets != read_secrets:
        logging.error("Validation failed: secrets do not match.")
        raise ValueError("Validation failed: secrets do not match.")
    else:
        logging.info("Validation successful: secrets match.")
