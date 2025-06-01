import json
from secretmanager import SecretManager

vault_url        = "https://192.168.86.60:8200"
ca_cert          = True
role             = "demo"
service_account  = "default"
transit_key      = "aes256-key"
namespace        = "default"
secret_name      = "matrix-secrets7"
secret_data_name = "secrets.json"

sm = SecretManager(vault_url, service_account, role, ca_cert)
k8s_enc_secret = sm.read_namespaced_secret(namespace, secret_name, secret_data_name)
decrypted_data = sm.decrypt_data_with_vault(transit_key, k8s_enc_secret)
secrets = json.loads(decrypted_data)
print(json.dumps(secrets, indent=2))