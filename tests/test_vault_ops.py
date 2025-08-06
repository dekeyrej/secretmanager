from unittest.mock import MagicMock, patch
from secretmanager._vault_ops import (
    connect_to_vault,
    _authenticate_vault_via_kubernetes,
    encrypt_data_with_vault,
    decrypt_data_with_vault,
    _rotate_vault_key,
    logout_vault,
)

# ─────────────────────────────────────────────────────────────
# connect_to_vault
# ─────────────────────────────────────────────────────────────


def test_connect_to_vault_default_ca():
    with patch("secretmanager._vault_ops.hvac.Client") as mock_client:
        client = connect_to_vault("https://vault.example.com")
        mock_client.assert_called_with(url="https://vault.example.com", verify=True)


def test_connect_to_vault_custom_ca():
    with patch("secretmanager._vault_ops.hvac.Client") as mock_client:
        client = connect_to_vault("https://vault.example.com", ca_path="/custom/ca.pem")
        mock_client.assert_called_with(
            url="https://vault.example.com", verify="/custom/ca.pem"
        )


# ─────────────────────────────────────────────────────────────
# _authenticate_vault_via_kubernetes
# ─────────────────────────────────────────────────────────────


def test_authenticate_success():
    mock_client = MagicMock()
    mock_client.auth.kubernetes.login.return_value = {
        "auth": {"client_token": "vault-token-123"}
    }
    token = _authenticate_vault_via_kubernetes(mock_client, "my-role", "jwt-token")
    assert token == "vault-token-123"


def test_authenticate_failure():
    mock_client = MagicMock()
    mock_client.auth.kubernetes.login.side_effect = Exception("Auth error")
    token = _authenticate_vault_via_kubernetes(mock_client, "my-role", "jwt-token")
    assert token is None


# ─────────────────────────────────────────────────────────────
# encrypt_data_with_vault
# ─────────────────────────────────────────────────────────────


@patch("secretmanager._vault_ops.crypto_utils.encode_data", return_value="encoded-data")
def test_encrypt_success(mock_encode):
    mock_client = MagicMock()
    mock_client.secrets.transit.encrypt_data.return_value = {
        "data": {"ciphertext": "vault-ciphertext"}
    }
    result = encrypt_data_with_vault(mock_client, "transit-key", "my-data")
    assert result == "vault-ciphertext"


@patch("secretmanager._vault_ops.crypto_utils.encode_data", return_value="encoded-data")
def test_encrypt_failure(mock_encode):
    mock_client = MagicMock()
    mock_client.secrets.transit.encrypt_data.side_effect = Exception("Encryption error")
    result = encrypt_data_with_vault(mock_client, "transit-key", "my-data")
    assert result is None


# ─────────────────────────────────────────────────────────────
# decrypt_data_with_vault
# ─────────────────────────────────────────────────────────────


@patch("secretmanager._vault_ops.crypto_utils.decode_data", return_value="decoded-data")
def test_decrypt_success(mock_decode):
    mock_client = MagicMock()
    mock_client.secrets.transit.decrypt_data.return_value = {
        "data": {"plaintext": "encoded-data"}
    }
    result = decrypt_data_with_vault(mock_client, "transit-key", "vault-ciphertext")
    assert result == "decoded-data"


@patch("secretmanager._vault_ops.crypto_utils.decode_data", return_value="decoded-data")
def test_decrypt_failure(mock_decode):
    mock_client = MagicMock()
    mock_client.secrets.transit.decrypt_data.side_effect = Exception("Decryption error")
    result = decrypt_data_with_vault(mock_client, "transit-key", "vault-ciphertext")
    assert result is None


# ─────────────────────────────────────────────────────────────
# _rotate_vault_key
# ─────────────────────────────────────────────────────────────


def test_rotate_success():
    mock_client = MagicMock()
    mock_client.secrets.transit.read_key.return_value = {"data": {"latest_version": 1}}
    mock_client.secrets.transit.rotate_key.return_value = {
        "data": {"latest_version": 2}
    }
    result = _rotate_vault_key(mock_client, "transit-key")
    assert result == {"status": "success"}


def test_rotate_no_change():
    mock_client = MagicMock()
    mock_client.secrets.transit.read_key.return_value = {"data": {"latest_version": 3}}
    mock_client.secrets.transit.rotate_key.return_value = {
        "data": {"latest_version": 3}
    }
    result = _rotate_vault_key(mock_client, "transit-key")
    assert result == {"status": "failure"}


def test_rotate_failure():
    mock_client = MagicMock()
    mock_client.secrets.transit.read_key.side_effect = Exception("Read error")
    result = _rotate_vault_key(mock_client, "transit-key")
    assert result is None


# ─────────────────────────────────────────────────────────────
# logout_vault
# ─────────────────────────────────────────────────────────────


def test_logout_success():
    mock_client = MagicMock()
    logout_vault(mock_client)
    mock_client.auth.token.revoke_self.assert_called_once()


def test_logout_failure():
    mock_client = MagicMock()
    mock_client.auth.token.revoke_self.side_effect = Exception("Logout error")
    logout_vault(mock_client)  # Should not raise
