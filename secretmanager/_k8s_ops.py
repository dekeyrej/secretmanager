import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def connect_to_k8s(kube_config=None):
    """ Connect to Kubernetes cluster using the provided kube config file """
    try:
        # Try to load the in-cluster configuration
        config.incluster_config.load_incluster_config()
        logger.info("In cluster configuration loaded.")
    except config.ConfigException:
        if kube_config:
            # Load kube config from the specified file
            config.load_kube_config(kube_config)
            logger.debug(f"Local kube config loaded from {kube_config}.")
        else:
            # Default to loading kube config from the default location (~/.kube/config)
            logger.debug("No config file provided, loading default kube config.")
            config.load_kube_config()
    logger.info("Connected to Kubernetes cluster successfully.")
    return client.CoreV1Api()
    

# the following methods handle Kubernetes service account token retrieval and secret management.
def get_k8s_service_account_token(k8s_client, service_account, namespace):
    """Retrieves the token associated with a Kubernetes service account."""
    """Creates a token request for the given service account."""
    try:
        api_response = k8s_client.create_namespaced_service_account_token(
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
        logger.error(f"Error requesting token: {e}")
        return None

def create_k8s_secret(k8s_client, namespace, secret_name, secret_data_name, data):
    """Creates or updates a Kubernetes secret with the given data."""
    from secretmanager._crypto_utils import encode_data
    
    secret = client.V1Secret(
        api_version="v1",
        kind="Secret",
        type="Opaque",
        metadata=client.V1ObjectMeta(name=secret_name),
        data= {secret_data_name: encode_data(data)}
    )
    
    try:
        k8s_client.create_namespaced_secret(namespace=namespace, body=secret)
        logger.info(f"Secret '{secret_name}' created in namespace '{namespace}'.")
    except client.ApiException as e:
        if e.status == 409:  # Conflict, secret already exists
            k8s_client.replace_namespaced_secret(name=secret_name, namespace=namespace, body=secret)
            logger.warning(f"Secret '{secret_name}' updated in namespace '{namespace}'.")
        else:
            logger.error(f"Error creating/updating secret: {e}")


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

def read_k8s_secret(k8s_client, secret_def: dict):
    from secretmanager._crypto_utils import decode_data
    """ routine to read an existing kubernetes secret or configmap. 
        Returns the whole map or a specific secret data name if provided """
    try:
        if secret_def['read_type'] == "SECRET":
            api_response = k8s_client.read_namespaced_secret(secret_def['secret_name'], secret_def['namespace'])
            logger.debug(f"Read Secret API response: \n{api_response}")
            if secret_def.get('read_key'):
                if secret_def['read_key'] not in api_response.data:
                    raise KeyError(f"Secret data '{secret_def['read_key']}' not found in the secret '{secret_def['secret_name']}'.")
                logger.debug(f"{secret_def['read_key']}: {decode_data(api_response.data[secret_def['read_key']])}")
                secrets = decode_data(api_response.data[secret_def['read_key']])
                return secrets   # return raw secret
            else:
                secrets = {}
                for data_name in api_response.data:
                    logger.debug(f"{data_name}: {decode_data(api_response.data[data_name])}")
                    secrets[data_name] = decode_data(api_response.data[data_name])
                return secrets # returns dict of all secrets in the secret
        elif secret_def['read_type'] == "CONFIG_MAP":
            api_response = k8s_client.read_namespaced_config_map(secret_def['secret_name'], secret_def['namespace'])
            logger.debug((f"Read ConfigMap API response: \n{api_response.data}"))
            secrets = {}
            for data_name in api_response.data:
                logger.debug(f"{data_name}: {api_response.data[data_name]}")
                secrets[data_name] = api_response.data[data_name]
            return secrets  # returns dict of all secrets in the configmap
    except client.exceptions.ApiException as apiex:
        logger.debug(apiex)
        return -1