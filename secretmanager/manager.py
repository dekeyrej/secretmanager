# import base64
# import json
import logging
# from kubernetes import client, config
# from kubernetes.client.rest import ApiException
# import hvac

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
#     "read_type": "CONFIG_MAP",   # or "SECRET" 
#     "read_key": None                  - reads all of the keys in the secret or configmap
# }
# or
# secretdef = {
#     "namespace": "default",
#     "secret_name": "common-config",
#     "read_type": "SECRET",
#     "read_key": "config.json"       # reads specific key in the secret
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
    """ A class to manage secrets from various sources: file, environment variables, Kubernetes, and Vault. """
    secret_types = {"FILE", "ENVIRONMENT", "KUBERNETES", "KUBEVAULT"}

    def __init__(self, config=None, log_level=logging.INFO):
        logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
        self.k8s_client = None
        self.hvac_client = None
        self.config = config
        if not self.config:
            logger.info("No configuration provided, using default settings.")
        elif self.config.get("SOURCE") not in self.secret_types:
            raise ValueError(f"Invalid configuration source. Must be one of: {', '.join(self.secret_types)}.")
        else:
            logger.info(f"SecretManager initialized with source: {self.config.get('SOURCE')}")
            if self.config.get("SOURCE") == "FILE":
                from secretmanager._source_loader import read_secrets_from_file
                self.read_secrets = read_secrets_from_file
            elif self.config.get("SOURCE") == "ENVIRONMENT":
                from secretmanager._source_loader import read_secrets_from_env
                self.read_secrets = read_secrets_from_env
            elif self.config.get("SOURCE") == "KUBERNETES":
                from secretmanager._k8s_ops import connect_to_k8s, read_k8s_secret
                self.k8s_client = connect_to_k8s(config.get("kube_config", None))
                self.read_secrets = read_k8s_secret
            elif self.config.get("SOURCE") == "KUBEVAULT":
                from secretmanager._k8s_ops import connect_to_k8s
                from secretmanager._vault_ops import connect_to_vault
                self.k8s_client = connect_to_k8s(config.get("kube_config", None))
                self.hvac_client = connect_to_vault(
                    self.config.get("vault_url"),
                    self.config.get("ca_cert", True))  # Default to True for using Python's CA bundle
                self.read_secrets = self.read_encrypted_secrets

    def configure_secret_type(self, config: dict):
        if config.get("SOURCE") not in self.secret_types:
            raise ValueError(f"Invalid configuration source. Must be one of: {', '.join(self.secret_types)}.")
        else:
            logger.info(f"SecretManager initialized with source: {config.get('SOURCE')}")
            self.config = config
            if config.get("SOURCE") == "FILE":
                from secretmanager._source_loader import read_secrets_from_file
                self.read_secrets = read_secrets_from_file
            elif config.get("SOURCE") == "ENVIRONMENT":
                from secretmanager._source_loader import read_secrets_from_env
                self.read_secrets = read_secrets_from_env
            elif config.get("SOURCE") == "KUBERNETES":
                from secretmanager._k8s_ops import connect_to_k8s, read_k8s_secret
                self.k8s_client = connect_to_k8s(config.get("kube_config", None))
                self.read_secrets = read_k8s_secret
            elif config.get("SOURCE") == "KUBEVAULT":
                from secretmanager._k8s_ops import connect_to_k8s
                from secretmanager._vault_ops import connect_to_vault
                self.k8s_client = connect_to_k8s(config.get("kube_config", None))
                self.hvac_client = connect_to_vault(config.get("vault_url"), config.get("ca_cert", True))  # Default to True for using Python's CA bundle
                self.read_secrets = self.read_encrypted_secrets

    def _authenticate_vault_via_kubernetes(self) -> bool:
        """Authenticates with Vault using Kubernetes auth method."""
        from secretmanager._k8s_ops import get_k8s_service_account_token
        from secretmanager._vault_ops import authenticate_vault_with_kubernetes
        if not self.hvac_client.is_authenticated():
            jwt = get_k8s_service_account_token(self.k8s_client, self.config.get("service_account"), self.config.get("namespace"))
            if not jwt:
                logger.error(f"Failed to retrieve service account token for '{self.config.get('service_account')}' in namespace '{self.config.get('namespace')}'.")
                return False
            self.hvac_client.token = authenticate_vault_with_kubernetes(self.hvac_client, self.config.get("role"), jwt)
            if not self.hvac_client.is_authenticated():
                logger.error("Vault authentication failed. Please check your credentials and configuration.")
                return False
            logger.info("Vault authentication successful.")
            return True
        # logger.info("Vault client is already authenticated.")
        return True

    def read_encrypted_secrets(self, secret_def: dict) -> dict:
        """Reads encrypted secrets from Kubernetes and decrypts them using Vault."""
        from secretmanager._source_loader import load_json_secrets
        from secretmanager._k8s_ops import read_k8s_secret
        from secretmanager._vault_ops import decrypt_data_with_vault
        k8s_enc_secret = read_k8s_secret(self.k8s_client, secret_def)[secret_def['secret_key']]
        logger.debug(k8s_enc_secret)  # ciphertext
        if k8s_enc_secret == -1:
            logger.error(f"Failed to read secret '{secret_def['secret_name']}' in namespace '{secret_def['namespace']}'.")
            return None
        transit_key = secret_def.get("transit_key", "None")
        if not transit_key:
            logger.error("Transit key is not specified.")
            return None
        status = self._authenticate_vault_via_kubernetes()
        if not status:
            logger.error("Failed to authenticate with Vault.")
            return None
        decrypted_data = decrypt_data_with_vault(self.hvac_client, transit_key, k8s_enc_secret)
        logger.debug(decrypted_data) # plaintext  After testing, don't print this out in production
        if decrypted_data is None:
            logger.error(f"Failed to decrypt data for secret '{secret_def['secret_name']}' in namespace '{secret_def['namespace']}'.")
            return None
        return load_json_secrets(decrypted_data)
    
    def create_encrypted_secret(self, secret_def: dict, data: str):
        """Creates or updates a Kubernetes secret with encrypted data."""
        from secretmanager._k8s_ops import create_k8s_secret
        from secretmanager._vault_ops import encrypt_data_with_vault
        transit_key = secret_def.get("transit_key", "None")
        if not transit_key:
            logger.error("Transit key is not specified.")
            return {"status": "failure"}
        status = self._authenticate_vault_via_kubernetes()
        if not status:
            logger.error("Failed to authenticate with Vault.")
            return None
        encrypted_data = encrypt_data_with_vault(self.hvac_client, transit_key, data)
        if not encrypted_data:
            logger.error(f"Failed to encrypt data for secret '{secret_def['secret_name']}' in namespace '{secret_def['namespace']}'.")
            return {"status": "failure"}
        create_k8s_secret(self.k8s_client, secret_def['namespace'], secret_def['secret_name'], secret_def['secret_key'], encrypted_data)
        logger.info(f"Successfully created/updated Kubernetes secret '{secret_def['secret_name']}' in namespace '{secret_def['namespace']}'.")
        return {"status": "success"}

    def rotate_vault_key(self, transit_key: str):
        from secretmanager._vault_ops import rotate_vault_key
        """Rotates a Vault transit key."""
        status = self._authenticate_vault_via_kubernetes()
        if not status:
            logger.error("Failed to authenticate with Vault.")
            return None
        rstatus = rotate_vault_key(self.hvac_client, transit_key)
        if rstatus['status'] == "failure":
            logger.error(f"Failed to rotate Vault key '{transit_key}'.")
            return {"status": "failure"}
        logger.info(f"Successfully rotated Vault key '{transit_key}'.")
        return {"status": "success"}
    
    def logout_vault(self):
        """Logs out of Vault."""
        from secretmanager._vault_ops import logout_vault
        if self.hvac_client and self.hvac_client.is_authenticated():
            logout_vault(self.hvac_client)
        else:
            logger.warning("Vault client is not authenticated, no logout action taken.")

    # def __del__(self):
    #     """Destructor to clean up resources."""
    #     if self.hvac_client:
    #         self.logout_vault()
    #     if self.k8s_client:
    #         logger.info("Kubernetes client connection closed.")
    #     logger.info("SecretManager instance deleted.")

    # def __repr__(self):
    #     return f"SecretManager(config={self.config}, log_level={logging.getLevelName(logger.level)})"

    # def __str__(self):
    #     return f"SecretManager with config: {self.config}, log level: {logging.getLevelName(logger.level)}"
