import base64
import json
import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import hvac

# secretcfg = {
#     "SOURCE": "FILE"
# }
#####
# secretdef = {
#     "file_name": "file.json",
#     "file_type": 'JSON'
# }

# secretcfg = {
#     "SOURCE": "ENVIRONMENT"
# }
#####
# secretdef = {
#     "definition": "env_definition.yaml",
#     "env_file": "env.env",
#     "definition_type": 'YAML'
# }

# secretcfg = {
#     "SOURCE": "KUBERNETES",
#     "kube_config": None
# }
#####
# secretdef = {
#     "namespace": "default", 
#     "secret_name": "common-config",
#     "read_type": "CONFIG_MAP"       # or "SECRET"
# }

# secretcfg = {
#     "SOURCE": "KUBEVAULT",
#     "kube_config": None,
#     "service_account": "default",
#     "namespace": "default",
#     "vault_url": "https://192.168.86.9:8200",
#     "role": "demo",
#     "ca_cert": True  # or path to CA cert file
# }
#####
# secretdef = {
#     "transit_key": "aes256-key",
#     "namespace": "default", 
#     "secret_name": "matrix-secrets",
#     "read_type": "SECRET",
#     "secret_key": "secrets.json"
# }

class SecretManager:
    def __init__(self, config, log_level=logging.INFO):
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        # self.SECRETS = ["FILE", "ENVIRONMENT", "KUBERNETES", "KUBEVAULT"]
        self.k8s_client = None
        self.hvac_client = None
        self.config = config
        if self.config.get("SOURCE") == "FILE":
            self.read_secrets = self.read_secrets_from_file
        elif self.config.get("SOURCE") == "ENVIRONMENT":
            self.read_secrets = self.read_secrets_from_env
        elif self.config.get("SOURCE") == "KUBERNETES":
            self.connect_to_k8s(self.config.get("kube_config", None))
            self.read_secrets = self.read_k8s_secret
        elif self.config.get("SOURCE") == "KUBEVAULT":
            self.connect_to_k8s(self.config.get("kube_config", None))
            self.connect_to_vault(
                self.config.get("vault_url"),
                self.config.get("role"),
                self.get_k8s_service_account_token(
                    self.config.get("service_account"),
                    self.config.get("namespace")
                ),
                ca_path=self.config.get("ca_cert", True)  # Default to True for using Python's CA bundle
            )
            self.read_secrets = self.read_encrypted_secrets
        else:
            raise ValueError("Invalid configuration source. Must be one of: FILE, ENVIRONMENT, KUBERNETES, KUBEVAULT.")

    
    def connect_to_k8s(self, kube_config=None):
        """ Connect to Kubernetes cluster using the provided kube config file """
        try:
            config.incluster_config.load_incluster_config()
            logging.info("In cluster configuration loaded.")
        except config.ConfigException:
            if kube_config:
                config.load_kube_config(kube_config)
                logging.debug(f"Local kube config loaded from {kube_config}.")
            else:
                # Default to loading kube config from the default location (~/.kube/config)
                logging.debug("No config file provided, loading default kube config.")
                config.load_kube_config()
        self.k8s_client = client.CoreV1Api()
        logging.info("Connected to Kubernetes cluster successfully.")

    def connect_to_vault(self, vault_url, role, k8s_token, ca_path=True):
        """ Connect to Vault using the provided parameters """
        if ca_path is True or ca_path == "True":
            logging.debug(f"Using python CA bundle")
            self.hvac_client = hvac.Client(url=vault_url, verify=True)
        else:
            logging.debug(f"Using custom CA bundle: {ca_path}")
            self.hvac_client = hvac.Client(url=vault_url, verify=ca_path)
        self.hvac_client.token = self.authenticate_vault_with_kubernetes(role, k8s_token)
        if self.hvac_client.is_authenticated():
            logging.info("Vault authentication successful.")
        else:
            logging.error("Vault authentication failed. Please check your credentials and configuration.")
            raise Exception("Vault authentication failed.")

    # the following methods handle reading text data from a file, well suited for reading a secrets file, 
    #   for encoding/encryption/storage in a kube secret.
    def read_data_from_file(self, file_path):
        with open(file_path, 'r') as file:
            return file.read()

    # The following method reads secrets from a file and returns them based on the specified secret type (JSON or YAML).
    def read_secrets_from_file(self, secrets_file, secret_type='JSON') -> dict:
        """ Return the loaded file secrets """
        try:
            rawsecrets = self.read_data_from_file(secrets_file)
            if secret_type == 'JSON':
                retval = self.load_json_secrets(rawsecrets)
            elif secret_type == 'YAML':
                retval = self.load_yaml_secrets(rawsecrets)
            else:   
                print(f"Unknown secret type '{secret_type}'.")
        except FileNotFoundError:
            raise FileNotFoundError(f"Secrets file '{secrets_file}' not found.")
        except Exception as e:
            raise Exception(f"Error reading secrets file '{secrets_file}': {e}")
        else:
            return retval

    # the following methods handle Kubernetes service account token retrieval and secret management.
    def get_k8s_service_account_token(self, service_account, namespace):
        """Retrieves the token associated with a Kubernetes service account."""
        """Creates a token request for the given service account."""
        try:
            api_response = self.k8s_client.create_namespaced_service_account_token(
                name=service_account,
                namespace=namespace,
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

        
    def read_k8s_secret(self, name, namespace, type, key=None):
        """ routine to read an existing kubernetes secret. 
            Returns the whole map or a specific secret data name if provided """
        try:
            if type == "SECRET":
                api_response = self.k8s_client.read_namespaced_secret(name, namespace)
                logging.debug(f"Read Secret API response: \n{api_response}")
                if key:
                    if key not in api_response.data:
                        raise KeyError(f"Secret data '{key}' not found in the secret '{name}'.")
                    logging.debug(f"{key}: {base64.b64decode(api_response.data[key]).decode('utf-8')}")
                    secrets = base64.b64decode(api_response.data[key]).decode('utf-8')
                    return secrets   # return raw secret
                else:
                    secrets = {}
                    for data_name in api_response.data:
                        logging.debug(f"{data_name}: {base64.b64decode(api_response.data[data_name]).decode('utf-8')}")
                        secrets[data_name] = base64.b64decode(api_response.data[data_name]).decode('utf-8')
                    return secrets # returns dict of all secrets in the secret
            elif type == "CONFIG_MAP":
                api_response = self.k8s_client.read_namespaced_config_map(name, namespace)
                logging.debug((f"Read ConfigMap API response: \n{api_response.data}"))
                secrets = {}
                for data_name in api_response.data:
                    logging.debug(f"{data_name}: {api_response.data[data_name]}")
                    secrets[data_name] = api_response.data[data_name]
                return secrets  # returns dict of all secrets in the secret
        except client.exceptions.ApiException as apiex:
            logging.debug(apiex)
            return -1
    
    # The following methods handle vault authentication (via kubernetes), encryption and decryption as a service, and key rotation using Vault's transit secrets engine.
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
            decrypted_data = self.decode_data(response['data']['plaintext'])
            return decrypted_data
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

    def read_encrypted_secrets(self, secret_name, namespace, read_type, read_key, transit_key) -> dict:
        """Reads encrypted secrets from Kubernetes and decrypts them using Vault."""
        k8s_enc_secret = self.read_k8s_secret(secret_name, namespace, read_type, read_key)
        logging.debug(k8s_enc_secret)
        if k8s_enc_secret == -1:
            logging.error(f"Failed to read secret '{secret_name}' in namespace '{namespace}'.")
            return None
        decrypted_data = self.decrypt_data_with_vault(transit_key, k8s_enc_secret)
        logging.debug(decrypted_data)
        if decrypted_data is None:
            logging.error(f"Failed to decrypt data for secret '{secret_name}' in namespace '{namespace}'.")
            return None
        return self.load_json_secrets(decrypted_data)

    # the following method supports reading secrets form the environment
    def read_secrets_from_env(self, env_definition, env_file=None, definition_type='JSON') -> dict:
        """ Reads secrets from environment variables or a .env file """
        import os
        import json
        import yaml
        
        if env_file:
            from dotenv import load_dotenv
            load_dotenv(env_file)
        
        secrets = {}
        if definition_type == 'JSON':
            try:
                with open(env_definition, 'r') as file:
                    env_definition = json.load(file)
            except FileNotFoundError:
                raise FileNotFoundError(f"Environment definition file '{env_definition}' not found.")
            except json.JSONDecodeError:
                raise ValueError(f"Invalid JSON format in '{env_definition}'.")
        elif definition_type == 'YAML':
            try:
                with open(env_definition, 'r') as file:
                    env_definition = yaml.safe_load(file)
            except FileNotFoundError:
                raise FileNotFoundError(f"Environment definition file '{env_definition}' not found.")
            except yaml.YAMLError:
                raise ValueError(f"Invalid YAML format in '{env_definition}'.")
        
        for key, env_var in env_definition.items():
            if env_var not in os.environ:
                raise KeyError(f"Environment variable '{env_var}' is not set.")
            secrets[key] = os.getenv(env_var)
        
        return secrets
    
    # The following methods handle encoding and decoding of data to/from base64.
    def encode_data(self, data):
        """Encodes data to base64."""
        return base64.b64encode(data.encode('utf-8')).decode('utf-8')
    def decode_data(self, data):
        """Decodes base64 encoded data."""
        return base64.b64decode(data.encode('utf-8')).decode('utf-8')
    
    # The following methods handle loading secrets from JSON or YAML strings.
    def load_json_secrets(self, rawsecrets):
        import json
        """ Load secrets from the specified file """
        try:
            return json.loads(rawsecrets)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError:
            return {}

    def load_yaml_secrets(self, rawsecrets):
        import yaml
        """ Load secrets from the specified file """
        try:
            return yaml.safe_load(rawsecrets)
        except FileNotFoundError:
            return {}
        except yaml.YAMLError:
            return {}

