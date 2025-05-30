import json
import base64
from pprint import pprint
import hvac                                           # HasiCorp Vault client library
from hvac.api.auth_methods import Kubernetes
from kubernetes import client, config                 # Kubernetes client library
from kubernetes.client.rest import ApiException

def read_secret(namespace, secret_name, data_name):
    """Reads a Kubernetes secret and returns its data."""
    try:
        config.load_kube_config()
        api_client = client.CoreV1Api()
        response = api_client.read_namespaced_secret(name=secret_name, namespace=namespace)
        secret_data = response.data.get(data_name)
        print(f"Secret data for '{data_name}' in secret '{secret_name}' in namespace '{namespace}': {secret_data}")  
        secret = json.loads(base64.b64decode(secret_data).decode('utf-8')) if secret_data else None
        return secret
    except ApiException as e:
        print(f"Error reading secret: {e}")
        return None

def create_token_request(namespace, service_account_name, expiration_seconds=600):
    """Creates a token request for the given service account."""
    try:
        config.load_kube_config()
        api_client = client.CoreV1Api()
       
        api_response = api_client.create_namespaced_service_account_token(
            name=service_account_name,
            namespace=namespace,
            body=client.AuthenticationV1TokenRequest(
                spec=client.V1TokenRequestSpec(
                    audiences=["https://kubernetes.default.svc"],
                    expiration_seconds=expiration_seconds
                )
            )
        )

        return api_response.status.token
    except ApiException as e:
        print(f"Error requesting token: {e}")
        return None
    
def kubernetes_vault_authenticated_client(vault_address, role, jwt, ca_cert_path=None):
    """Authenticate with Vault using Kubernetes auth method."""
    client = hvac.Client(url=vault_address, verify=ca_cert_path)
    client.token = Kubernetes(client.adapter).login(role=role, jwt=jwt, mount_point='kubernetes')['auth']['client_token']
    if not client.is_authenticated():
        print("Vault authentication failed.")
        return None
    else:
        print("Vault authentication successful.")
        return client
    
if __name__ == '__main__':

    # with open('secrets.json', 'r') as f:
    #     secrets = json.load(f)

    secrets = read_secret("default", "matrix-secrets", "secrets.json")
    # secret_name = "matrix-secret"
    # secret_namespace = "default"
    service_account_name = "default"
    service_account_namespace = "default"

    vault_url="https://192.168.86.60:8200"
    cacert='ca.crt'  # Path to your CA certificate file, if using private Certificate Authority
    role="demo"

    sa_token = create_token_request(service_account_namespace, service_account_name)
    if sa_token:
        client = kubernetes_vault_authenticated_client(vault_url, role, sa_token, ca_cert_path=cacert)
        if not client:
            exit(1)
        ciphertext = client.secrets.transit.encrypt_data("aes256-key", plaintext=base64.b64encode(json.dumps(secrets).encode('utf-8')).decode('utf-8'))['data']['ciphertext']
        plaintext  = client.secrets.transit.decrypt_data("aes256-key", ciphertext=ciphertext)['data']['plaintext']
        # client.secrets.transit.rotate_key("aes256-key")
        pprint(f"Original  data: {secrets}")
        print(f"Encrypted data: {ciphertext}")
        pprint(f"Decrypted data: {json.loads(base64.b64decode(plaintext).decode('utf-8'))}")
    else:
        print(f"Could not retrieve token for service account '{service_account_name}'.")

