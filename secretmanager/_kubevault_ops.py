import logging

from secretmanager.manager import SecretManager

from secretmanager._k8s_ops import (
    connect_to_k8s,
    _get_k8s_service_account_token,
    read_k8s_secret,
    create_k8s_secret,
)

from secretmanager._vault_ops import (
    connect_to_vault,
    _authenticate_vault_via_kubernetes,
    decrypt_data_with_vault,
    encrypt_data_with_vault,
    _rotate_vault_key,
    logout_vault,
)
from secretmanager._source_loader import load_json_secrets

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
#     "read_key": "secrets.json"
# }


# @register("KUBEVAULT", "INIT")
def init_kubevault(manager: SecretManager):
    """Initializes the KubeVault client with the provided configuration."""
    k8s_client = connect_to_k8s(manager)
    hvac_client = connect_to_vault(
        manager.config.get("vault_url"), manager.config.get("ca_cert", True)
    )
    if not hvac_client.is_authenticated():
        jwt = _get_k8s_service_account_token(
            k8s_client,
            manager.config.get("service_account"),
            manager.config.get("namespace"),
        )["data"]
        if not jwt:
            logger.error(
                f"Failed to retrieve service account token for \
                    '{manager.config.get('service_account')}' in \
                        namespace '{manager.config.get('namespace')}'."
            )
            return {"status": "failure", "verb": "INIT", "source": "KUBEVAULT"}
        hvac_client.token = _authenticate_vault_via_kubernetes(
            hvac_client, manager.config.get("role"), jwt
        )
        if not hvac_client.is_authenticated():
            logger.error(
                "Vault authentication failed. Please check your credentials and configuration."
            )
            return {"status": "failure", "verb": "INIT", "source": "KUBEVAULT"}
        logger.info("Vault authentication successful.")

    manager.k8s_client = k8s_client
    manager.hvac_client = hvac_client
    return {"status": "success", "verb": "INIT", "source": "KUBEVAULT"}


def reauthenticate_vault_via_kubernetes(manager: SecretManager) -> bool:
    """Authenticates with Vault using Kubernetes auth method."""
    jwt = _get_k8s_service_account_token(
        manager.k8s_client,
        manager.config.get("service_account"),
        manager.config.get("namespace"),
    )["data"]
    if not jwt:
        logger.error(
            f"Failed to retrieve service account token for \
                '{manager.config.get('service_account')}' \
                    in namespace '{manager.config.get('namespace')}'."
        )
        return False
    manager.hvac_client.token = _authenticate_vault_via_kubernetes(
        manager.hvac_client, manager.config.get("role"), jwt
    )
    if not manager.hvac_client.is_authenticated():
        logger.error(
            "Vault authentication failed. Please check your credentials and configuration."
        )
        return False
    logger.info("Vault authentication successful.")
    return True


# @register("KUBEVAULT", "READ")
def read_encrypted_secrets(manager: SecretManager, secret_def: dict) -> dict:
    """Reads encrypted secrets from Kubernetes and decrypts them using Vault."""
    k8s_enc_secret = read_k8s_secret(manager, secret_def)[
        "data"
    ]  # [secret_def['read_key']]
    logger.debug(k8s_enc_secret)  # ciphertext
    if k8s_enc_secret == -1:
        logger.error(
            f"Failed to read secret '{secret_def['secret_name']}' \
                in namespace '{secret_def['namespace']}'."
        )
        return {"status": "failure", "verb": "READ", "source": "KUBEVAULT"}
    transit_key = secret_def.get("transit_key")
    if not transit_key:
        logger.error("Transit key is not specified.")
        return {"status": "failure", "verb": "READ", "source": "KUBEVAULT"}
    if not manager.hvac_client.is_authenticated():
        status = reauthenticate_vault_via_kubernetes(manager)
        if not status:
            logger.error("Failed to authenticate with Vault.")
            return {"status": "failure", "verb": "READ", "source": "KUBEVAULT"}
    decrypted_data = decrypt_data_with_vault(
        manager.hvac_client, transit_key, k8s_enc_secret
    )
    logger.debug(
        decrypted_data
    )  # plaintext  After testing, don't print this out in production
    if decrypted_data is None:
        logger.error(
            f"Failed to decrypt data for secret '{secret_def['secret_name']}' \
                in namespace '{secret_def['namespace']}'."
        )
        return {"status": "failure", "verb": "READ", "source": "KUBEVAULT"}
    return {
        "status": "success",
        "verb": "READ",
        "source": "KUBEVAULT",
        "data": load_json_secrets(decrypted_data),
    }


# @register("KUBEVAULT", "CREATE")
def create_encrypted_secret(
    manager: SecretManager, secret_def: dict, data: str
) -> dict:
    """Creates or updates a Kubernetes secret with encrypted data."""
    transit_key = secret_def.get("transit_key")
    if not transit_key:
        logger.error("Transit key is not specified.")
        return {"status": "failure", "verb": "CREATE", "source": "KUBEVAULT"}
    if not manager.hvac_client.is_authenticated():
        status = reauthenticate_vault_via_kubernetes(manager)
        if not status:
            logger.error("Failed to authenticate with Vault.")
            return {"status": "failure", "verb": "READ", "source": "KUBEVAULT"}
    encrypted_data = encrypt_data_with_vault(manager.hvac_client, transit_key, data)
    if not encrypted_data:
        logger.error(
            f"Failed to encrypt data for secret '{secret_def['secret_name']}' \
                in namespace '{secret_def['namespace']}'."
        )
        return {"status": "failure", "verb": "CREATE", "source": "KUBEVAULT"}
    create_k8s_secret(manager, secret_def, encrypted_data)
    logger.info(
        f"Successfully created/updated Kubernetes secret '{secret_def['secret_name']}' \
            in namespace '{secret_def['namespace']}'."
    )
    return {"status": "success", "verb": "CREATE", "source": "KUBEVAULT"}


# @register("KUBEVAULT", "ROTATE")
def rotate_vault_key(manager: SecretManager, transit_key: str) -> dict:
    """Rotates a Vault transit key."""
    if not manager.hvac_client.is_authenticated():
        status = reauthenticate_vault_via_kubernetes(manager)
        if not status:
            logger.error("Failed to authenticate with Vault.")
            return {"status": "failure", "verb": "READ", "source": "KUBEVAULT"}
    rstatus = _rotate_vault_key(manager.hvac_client, transit_key)
    if rstatus["status"] == "failure":
        logger.error(f"Failed to rotate Vault key '{transit_key}'.")
        return {"status": "failure", "verb": "ROTATE", "source": "KUBEVAULT"}
    logger.info(f"Successfully rotated Vault key '{transit_key}'.")
    return {"status": "success", "verb": "ROTATE", "source": "KUBEVAULT"}


# @register("KUBEVAULT", "LOGOUT")
def logout_kubevault(manager: SecretManager) -> dict:
    """Logs out of KubeVault."""
    if manager.hvac_client and manager.hvac_client.is_authenticated():
        logout_vault(manager.hvac_client)
        logger.info("Logged out of Vault successfully.")
    else:
        logger.warning("No active Vault session to log out from.")
    manager.hvac_client = None
    manager.k8s_client = None
    logger.info("KubeVault client reset successfully.")
    return {"status": "success", "verb": "LOGOUT", "source": "KUBEVAULT"}
