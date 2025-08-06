import logging

# from typing import Dict, Any
import hvac
import secretmanager._crypto_utils as crypto_utils

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def connect_to_vault(vault_url, ca_path=True):
    """Connect to Vault using the provided parameters"""
    if ca_path is True or ca_path == "True":
        logging.debug("Using python CA bundle")
        hvac_client = hvac.Client(url=vault_url, verify=True)
    else:
        logging.debug(f"Using custom CA bundle: {ca_path}")
        hvac_client = hvac.Client(url=vault_url, verify=ca_path)
    return hvac_client


# The following methods handle vault authentication (via kubernetes),
# encryption and decryption as a service, and key rotation using
# Vault's transit secrets engine.
def _authenticate_vault_via_kubernetes(hvac_client, role, jwt):
    """Authenticates with Vault using Kubernetes auth method."""
    try:
        auth_response = hvac_client.auth.kubernetes.login(
            role=role, jwt=jwt, mount_point="kubernetes"
        )
        return auth_response["auth"]["client_token"]
    except Exception as e:
        logger.error(f"Error authenticating with Vault: {e}")
        return None


def encrypt_data_with_vault(hvac_client, transit_key, data):
    """Encrypts data using a Vault transit key."""
    try:
        response = hvac_client.secrets.transit.encrypt_data(
            name=transit_key, plaintext=crypto_utils.encode_data(data)
        )
        encrypted_data = response["data"]["ciphertext"]
        return encrypted_data
    except Exception as e:
        logger.error(f"Error encrypting data with Vault: {e}")
        return None


def decrypt_data_with_vault(hvac_client, transit_key, data):
    logger.debug(f"Passed data to decrypt_data_with_vault: {data}")
    """Decrypts data using a Vault transit key."""
    try:
        response = hvac_client.secrets.transit.decrypt_data(
            name=transit_key, ciphertext=data
        )
        decrypted_data = crypto_utils.decode_data(response["data"]["plaintext"])
        return decrypted_data
    except Exception as e:
        logger.error(f"Error decrypting data with Vault: {e}")
        return None


def _rotate_vault_key(hvac_client, transit_key):
    """Rotates a Vault transit key."""
    try:
        current_key = hvac_client.secrets.transit.read_key(name=transit_key)
        logger.debug(
            f"Current Key Version: \
                     '{current_key['data']['latest_version']}'"
        )
        # logger.debug(f"Current Key: '{current_key['data']['keys'][0]}'")
        response = hvac_client.secrets.transit.rotate_key(name=transit_key)
        logger.debug(f"New Version: '{response['data']['latest_version']}'")
        if response["data"]["latest_version"] == current_key["data"]["latest_version"]:
            logger.warning(
                f"Vault key '{transit_key}' was not rotated. It is \
                    still at version {current_key['data']['latest_version']}."
            )
            return {"status": "failure"}
        else:
            logger.debug(
                f"Vault key '{transit_key}' rotated successfully \
                    to version {response['data']['latest_version']}."
            )
            return {"status": "success"}
    except Exception as e:
        logger.error(f"Error rotating Vault key: {e}")


def logout_vault(hvac_client):
    """Logs out of Vault."""
    try:
        hvac_client.auth.token.revoke_self()
        logger.info("Logged out of Vault successfully.")
    except Exception as e:
        logger.error(f"Error logging out of Vault: {e}")
