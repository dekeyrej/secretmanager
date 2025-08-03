import logging

from secretmanager import SecretManager

log_level   = "INFO"
secretcfg = {
    "SOURCE": "KUBERNETES",
    "kube_config": None
}
sm = SecretManager(secretcfg, log_level)
k8s_client = sm.k8s_client

secrets = {}

# read multiple secret data values from one secret
secretdef1 = {
    "secret_name": "telegraf-secrets",
    "namespace": "iot",
    "read_type": "SECRET",
    "read_key": None
}
secrets.update(sm.read_secrets(k8s_client, secretdef1))

# read multiple configMap data values from one configMap
secretdef2 = {
    "secret_name": "common-config",
    "namespace": "default",
    "read_type": "CONFIG_MAP",
    "read_key": None
}
secrets.update(sm.read_secrets(k8s_client, secretdef2))

# read single secret data value (by key) from one secret
secretdef3 = {
    "secret_name": "ghcr-login-secret",
    "namespace": "default",
    "read_type": "SECRET",
    "read_key": ".dockerconfigjson"
}
secrets.update({secretdef3["read_key"]: sm.read_secrets(k8s_client, secretdef3)})

logging.info("Combined Secrets:")
for key in secrets:
    print(f"{key}: {secrets[key]}")
