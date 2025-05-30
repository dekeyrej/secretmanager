import base64
import logging
import os
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import hvac

class SecretManager:
    def __init__(self, vault_url, service_account, role, ca_path=True, k8s_namespace='default', log_level=logging.INFO):
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        self.vault_url = vault_url
        self.namespace = k8s_namespace
        self.role = role
        if os.getenv("PROD") == "1":
            config.load_incluster_config()  # Running inside the cluster
        else:
            config.load_kube_config()  # Running locally
        self.k8s_client = client.CoreV1Api()
        self.hvac_client = hvac.Client(url=vault_url, verify=ca_path)
        self.hvac_client.token = self.authenticate_vault_with_kubernetes(role, self.get_service_account_token(service_account))
        if self.hvac_client.is_authenticated():
            logging.info("Vault authentication successful.")
        else:
            logging.error("Vault authentication failed. Please check your credentials and configuration.")
            raise Exception("Vault authentication failed.")
    
    def get_service_account_token(self, service_account):
        """Retrieves the token associated with a Kubernetes service account."""
        """Creates a token request for the given service account."""
        try:
            api_response = self.k8s_client.create_namespaced_service_account_token(
                name=service_account,
                namespace=self.namespace,
                body=client.AuthenticationV1TokenRequest(
                    spec=client.V1TokenRequestSpec(
                        audiences=["https://kubernetes.default.svc"],
                        expiration_seconds=600
                    )
                )
            )

            return api_response.status.token
        except ApiException as e:
            logging.error(f"Error requesting token: {e}")
            return None

    def authenticate_vault_with_kubernetes(self, role, jwt):
        """Authenticates with Vault using Kubernetes auth method."""
        try:
            auth_response = self.hvac_client.auth.kubernetes.login(
                role=role,
                jwt=jwt,
                mount_point='kubernetes'
            )
            return auth_response['auth']['client_token']
        except Exception as e:
            logging.error(f"Error authenticating with Vault: {e}")
            return None

    def read_data_from_file(self, file_path):
        """Reads secrets from a JSON or YAML file."""
        with open(file_path, 'r') as file:
            return file.read()

    def create_k8s_secret(self, namespace, secret_name, secret_data_name, data):
        """Creates or updates a Kubernetes secret with the given data."""
        
        secret = client.V1Secret(
            api_version="v1",
            kind="Secret",
            type="Opaque",
            metadata=client.V1ObjectMeta(name=secret_name),
            data= {secret_data_name: self.encode_data(data)}
        )
        
        try:
            self.k8s_client.create_namespaced_secret(namespace=namespace, body=secret)
            logging.info(f"Secret '{secret_name}' created in namespace '{namespace}'.")
        except client.ApiException as e:
            if e.status == 409:  # Conflict, secret already exists
                self.k8s_client.replace_namespaced_secret(name=secret_name, namespace=namespace, body=secret)
                logging.warning(f"Secret '{secret_name}' updated in namespace '{namespace}'.")
            else:
                logging.error(f"Error creating/updating secret: {e}")

    def read_namespaced_secret(self, namespace, secret_name, data_name):
        """Reads a Kubernetes secret and returns its data."""
        try:
            response = self.k8s_client.read_namespaced_secret(name=secret_name, namespace=namespace)
            return self.decode_data(response.data[data_name]) if data_name in response.data else None
        except ApiException as e:
            logging.error(f"Error reading secret: {e}")
            return None
    
    def encrypt_data_with_vault(self, transit_key, data):
        """Encrypts data using a Vault transit key."""
        try:
            response = self.hvac_client.secrets.transit.encrypt_data(
                name=transit_key,
                plaintext=base64.b64encode(data.encode('utf-8')).decode('utf-8')
            )
            encrypted_data = response['data']['ciphertext']
            return encrypted_data
        except Exception as e:
            logging.error(f"Error encrypting data with Vault: {e}")
            return None
    
    def decrypt_data_with_vault(self, transit_key, data):
        """Decrypts data using a Vault transit key."""
        try:
            response = self.hvac_client.secrets.transit.decrypt_data(
                name=transit_key,
                ciphertext=data
            )
            encrypted_data = self.decode_data(response['data']['plaintext'])
            return encrypted_data
        except Exception as e:
            logging.error(f"Error decrypting data with Vault: {e}")
            return None
    def rotate_vault_key(self, transit_key):
        """Rotates a Vault transit key."""
        try:
            self.hvac_client.secrets.transit.rotate_key(name=transit_key)
            logging.info(f"Vault key '{transit_key}' rotated successfully.")
        except Exception as e:
            logging.error(f"Error rotating Vault key: {e}")
    
    def encode_data(self, data):
        """Encodes data to base64."""
        return base64.b64encode(data.encode('utf-8')).decode('utf-8')
    def decode_data(self, data):
        """Decodes base64 encoded data."""
        return base64.b64decode(data.encode('utf-8')).decode('utf-8')
