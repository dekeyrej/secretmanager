import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException

from secretmanager.manager import SecretManager

import secretmanager._crypto_utils as crypto_utils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# secretcfg = {
#     "SOURCE": "KUBERNETES",
#     "kube_config": None
# }
#####
# secretdef = {
#     "namespace": "default",
#     "secret_name": "common-config",
#     "read_type": "CONFIG_MAP",   # or "SECRET"
#     "read_key": None               - reads all keys in secret or configmap
# }
# or
# secretdef = {
#     "namespace": "default",
#     "secret_name": "common-config",
#     "read_type": "SECRET",
#     "read_key": "config.json"       # reads specific key in the secret
# }


# @register("KUBERNETES", "INIT")
def connect_to_k8s(manager: SecretManager):
    """Connect to Kubernetes cluster using the provided kube config file"""
    kube_config = manager.config.get("kube_config", None)
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
            # Default to loading kube config from the default (~/.kube/config)
            logger.debug("No config file provided, loading default config.")
            config.load_kube_config()
    logger.info("Connected to Kubernetes cluster successfully.")
    manager.k8s_client = client.CoreV1Api()  # Initialize the Kubernetes client
    return manager.k8s_client


# methods handle Kubernetes service account token retrieval for KubeVault.
def _get_k8s_service_account_token(k8s_client, service_account, namespace):
    """Retrieves the token associated with a Kubernetes service account."""
    """Creates a token request for the given service account."""
    try:
        api_response = k8s_client.create_namespaced_service_account_token(
            name=service_account,
            namespace=namespace,
            body=client.AuthenticationV1TokenRequest(
                spec=client.V1TokenRequestSpec(
                    audiences=["https://kubernetes.default.svc"], expiration_seconds=600
                )
            ),
        )

        return {"status": "success", "data": api_response.status.token}
    except ApiException as e:
        logger.error(f"Error requesting token: {e}")
        return {"status": "failure", "error": str(e)}


# @register("KUBERNETES", "CREATE")
def create_k8s_secret(manager: SecretManager, secret_def: dict, data) -> dict:
    """Creates or updates a Kubernetes secret with the given data."""
    # from secretmanager._crypto_utils import encode_data

    secret = client.V1Secret(
        api_version="v1",
        kind="Secret",
        type="Opaque",
        metadata=client.V1ObjectMeta(name=secret_def["secret_name"]),
        data={secret_def["read_key"]: crypto_utils.encode_data(data)},
    )

    try:
        manager.k8s_client.create_namespaced_secret(
            namespace=secret_def["namespace"], body=secret
        )
        logger.info(
            f"Secret '{secret_def['secret_name']}' created in namespace \
                '{secret_def['namespace']}'."
        )
        return {"status": "success", "verb": "CREATE", "source": "KUBERNETES"}
    except client.ApiException as e:
        if e.status == 409:  # Conflict, secret already exists
            manager.k8s_client.replace_namespaced_secret(
                name=secret_def["secret_name"],
                namespace=secret_def["namespace"],
                body=secret,
            )
            logger.warning(
                f"Secret '{secret_def['secret_name']}' updated in namespace \
                     '{secret_def['namespace']}'."
            )
            return {"status": "success", "verb": "CREATE", "source": "KUBERNETES"}
        else:
            logger.error(f"Error creating/updating secret: {e}")
            return {"status": "failure", "verb": "CREATE", "source": "KUBERNETES"}


# secretdef = {
#     "namespace": "default",
#     "secret_name": "common-config",
#     "read_type": "CONFIG_MAP",   # or "SECRET"
#     "read_key": None             - reads all keys in the secret or configmap
# }
# or
# secretdef = {
#     "namespace": "default",
#     "secret_name": "common-config",
#     "read_type": "SECRET",
#     "read_key": "config.json"       # reads specific key in the secret
# }


# @register("KUBERNETES", "READ")
def read_k8s_secret(manager: SecretManager, secret_def: dict):
    # from secretmanager._crypto_utils import decode_data
    """routine to read an existing kubernetes secret or configmap.
    Returns the whole map or a specific secret data name if provided"""
    try:
        if secret_def["read_type"] == "SECRET":
            api_response = manager.k8s_client.read_namespaced_secret(
                secret_def["secret_name"], secret_def["namespace"]
            )
            logger.debug(f"Read Secret API response: \n{api_response}")
            if secret_def.get("read_key"):
                if secret_def["read_key"] not in api_response.data:
                    raise KeyError(
                        f"Secret data '{secret_def['read_key']}' \
                            not found in the secret '{secret_def['secret_name']}'."
                    )
                logger.debug(
                    f"{secret_def['read_key']}: \
                        {crypto_utils.decode_data(api_response.data[secret_def['read_key']])}"
                )
                secrets = crypto_utils.decode_data(
                    api_response.data[secret_def["read_key"]]
                )
                return {
                    "status": "success",
                    "verb": "READ",
                    "source": "KUBERNETES",
                    "data": secrets,
                }  # return raw secret
            else:
                secrets = {}
                for data_name in api_response.data:
                    logger.debug(
                        f"{data_name}: {crypto_utils.decode_data(api_response.data[data_name])}"
                    )
                    secrets[data_name] = crypto_utils.decode_data(
                        api_response.data[data_name]
                    )
                return {
                    "status": "success",
                    "verb": "READ",
                    "source": "KUBERNETES",
                    "data": secrets,
                }  # returns dict of all secrets in the secret
        elif secret_def["read_type"] == "CONFIG_MAP":
            api_response = manager.k8s_client.read_namespaced_config_map(
                secret_def["secret_name"], secret_def["namespace"]
            )
            logger.debug(
                (
                    f"Read ConfigMap API response: \n \
                          {api_response.data}"
                )
            )
            secrets = {}
            for data_name in api_response.data:
                logger.debug(f"{data_name}: {api_response.data[data_name]}")
                secrets[data_name] = api_response.data[data_name]
            return {
                "status": "success",
                "verb": "READ",
                "source": "KUBERNETES",
                "data": secrets,
            }  # returns dict of all secrets in the configmap
    except client.exceptions.ApiException as apiex:
        logger.debug(apiex)
        return {
            "status": "failure",
            "verb": "READ",
            "source": "KUBERNETES",
            "error": str(apiex),
        }
    except KeyError as ke:
        logger.error(f"Key error: {ke}")
        return {
            "status": "failure",
            "verb": "READ",
            "source": "KUBERNETES",
            "error": str(ke),
        }
    except Exception as e:
        logger.error(f"An error occurred while reading the secret: {e}")
        return {
            "status": "failure",
            "verb": "READ",
            "source": "KUBERNETES",
            "error": str(e),
        }


def logout_k8s(manager: SecretManager) -> dict:
    """Logs out of Vault."""
    manager.k8s_client = None
    logger.info("K8s client reset successfully.")
    return {"status": "success", "verb": "LOGOUT", "source": "KUBERNETES"}
