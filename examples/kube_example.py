import logging
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../secretmanager')))

from secretmanager import SecretManager

log_level   = "INFO"
config = {
    "SOURCE": "KUBERNETES",
    "kube_config": None
}
secret_name = "matrix-secret-environment"
namespace   = "default"
read_type   = "SECRET"  # or "CONFIG_MAP
read_key    =  None

secrets = {}

sm = SecretManager(config, log_level)
sm.connect_to_k8s()

# read multiple secret data values from one secret
secrets.update(sm.read_secrets(secret_name, namespace, read_type, read_key))

# read multiple configMap data values from one configMap
secret_name = "common-config"
read_type   = "CONFIG_MAP"
secrets.update(sm.read_secrets(secret_name, namespace, read_type, read_key))

# read multiple configMap data values from one configMap
secret_name = "app-config"
secrets.update(sm.read_secrets(secret_name, namespace, read_type, read_key))

# read single secret data value (by key) from one secret
secret_name = "matrix-secrets"
read_type   = "SECRET"
read_key    = "secrets.json"              # Only used if read_type is "SECRET" and you want to read a specific key
secrets.update({read_key: sm.read_secrets(secret_name, namespace, read_type, read_key)})

logging.info("Combined Secrets:")
for key in secrets:
    print(f"{key}: {secrets[key]}")
