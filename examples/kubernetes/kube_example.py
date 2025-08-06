import logging

from secretmanager import SecretManager

log_level   = "INFO"
secretcfg = {
    "SOURCE": "KUBERNETES",
    "kube_config": None
}
sm = SecretManager(secretcfg, log_level)

secrets = {}

# read multiple secret data values from one secret
secretdef1 = {
    "secret_name": "telegraf-secrets",
    "namespace": "iot",
    "read_type": "SECRET",
    "read_key": None
}
msresult = sm.execute("KUBERNETES", "READ", sm, secretdef1)
if msresult.get("status") == "success":
    logging.debug(f"Read Secret: {msresult.get('data')}")
    secrets.update(msresult.get("data"))


# read multiple configMap data values from one configMap
secretdef2 = {
    "secret_name": "common-config",
    "namespace": "default",
    "read_type": "CONFIG_MAP",
    "read_key": None
}
cmresult = sm.execute("KUBERNETES", "READ", sm, secretdef2)
if cmresult.get("status") == "success":
    logging.debug(f"Read ConfigMap: {cmresult.get('data')}")
    secrets.update(cmresult.get("data"))

# read single secret data value (by key) from one secret
secretdef3 = {
    "secret_name": "ghcr-login-secret",
    "namespace": "default",
    "read_type": "SECRET",
    "read_key": ".dockerconfigjson"
}
ssresult = sm.execute("KUBERNETES", "READ", sm, secretdef3)
if ssresult.get("status") == "success":
    logging.debug(f"Read Secret: {ssresult.get('data')}")
    secrets.update({secretdef3["read_key"]: ssresult.get("data")})

logging.info("Combined Secrets:")
for key in secrets:
    print(f"{key}: {secrets[key]}")
