from unittest.mock import MagicMock, patch
from secretmanager.manager import SecretManager

# import secretmanager._k8s_ops
# print(secretmanager._k8s_ops.decode_data)
from secretmanager._k8s_ops import (
    connect_to_k8s,
    _get_k8s_service_account_token,
    create_k8s_secret,
    read_k8s_secret,
    logout_k8s,
)
from kubernetes.client.rest import ApiException
from kubernetes import config, client


# --- connect_to_k8s ---
@patch("secretmanager._k8s_ops.config.incluster_config.load_incluster_config")
@patch("secretmanager._k8s_ops.client.CoreV1Api")
def test_connect_to_k8s_incluster(mock_corev1, mock_incluster):
    manager = SecretManager()
    manager.config = {"kube_config": None}
    api = connect_to_k8s(manager)

    mock_incluster.assert_called_once()
    mock_corev1.assert_called_once()
    assert api == mock_corev1()


@patch(
    "secretmanager._k8s_ops.config.incluster_config.load_incluster_config",
    side_effect=config.ConfigException("Not in cluster"),
)
@patch("secretmanager._k8s_ops.config.load_kube_config")
@patch("secretmanager._k8s_ops.client.CoreV1Api")
def test_connect_to_k8s_local_noconfig(mock_corev1, mock_load_config, mock_incluster):
    manager = SecretManager()
    manager.config = {"kube_config": None}
    api = connect_to_k8s(manager)

    mock_incluster.assert_called_once()
    mock_corev1.assert_called_once()
    assert api == mock_corev1()


@patch(
    "secretmanager._k8s_ops.config.incluster_config.load_incluster_config",
    side_effect=config.ConfigException("Not in cluster"),
)
@patch("secretmanager._k8s_ops.config.load_kube_config")
@patch("secretmanager._k8s_ops.client.CoreV1Api")
def test_connect_to_k8s_local_withconfig(mock_corev1, mock_load_config, mock_incluster):
    manager = SecretManager()
    manager.config = {"kube_config": "/path/to/kubeconfig"}
    api = connect_to_k8s(manager)

    mock_incluster.assert_called_once()
    mock_load_config.assert_called_once_with("/path/to/kubeconfig")
    mock_corev1.assert_called_once()
    assert api == mock_corev1()


# --- _get_k8s_service_account_token ---
def test_get_k8s_service_account_token_success():
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.status.token = "fake-token"
    mock_client.create_namespaced_service_account_token.return_value = mock_response

    token = _get_k8s_service_account_token(mock_client, "my-sa", "default")["data"]
    assert token == "fake-token"


def test_get_k8s_service_account_token_failure():
    mock_client = MagicMock()
    mock_client.create_namespaced_service_account_token.side_effect = ApiException(
        "API error"
    )
    token = _get_k8s_service_account_token(mock_client, "my-sa", "default")
    assert token["status"] == "failure"
    assert "error" in token


# --- create_k8s_secret ---
@patch("secretmanager._k8s_ops.crypto_utils.encode_data", return_value="ZW5jb2RlZA==")
def test_create_k8s_secret_create(mock_encode):
    mock_k8s_client = MagicMock()
    manager = SecretManager()
    manager.k8s_client = mock_k8s_client
    # manager.k8s_client.create_namespaced_secret.return_value = None
    secret_def = {
        "namespace": "default",
        "secret_name": "my-secret",
        "read_type": "SECRET",
        "read_key": "config.json",
    }
    result = create_k8s_secret(manager, secret_def, "secret-value")
    mock_k8s_client.create_namespaced_secret.assert_called_once()
    assert result["status"] == "success"
    assert result["verb"] == "CREATE"
    assert result["source"] == "KUBERNETES"


# test5
@patch("secretmanager._k8s_ops.crypto_utils.encode_data", return_value="ZW5jb2RlZA==")
def test_create_k8s_secret_conflict(mock_encode):
    mock_k8s_client = MagicMock()
    manager = SecretManager()
    manager.k8s_client = mock_k8s_client
    conflict_exception = ApiException("Conflict")
    conflict_exception.status = 409
    manager.k8s_client.create_namespaced_secret.side_effect = conflict_exception
    secret_def = {
        "namespace": "default",
        "secret_name": "my-secret",
        "read_type": "SECRET",
        "read_key": "config.json",
    }
    result = create_k8s_secret(manager, secret_def, "secret-value")
    mock_k8s_client.replace_namespaced_secret.assert_called_once()
    assert result["status"] == "success"
    assert result["verb"] == "CREATE"
    assert result["source"] == "KUBERNETES"


@patch("secretmanager._k8s_ops.crypto_utils.encode_data", return_value="ZW5jb2RlZA==")
def test_create_k8s_secret_notfound(mock_encode):
    mock_k8s_client = MagicMock()
    manager = SecretManager()
    manager.k8s_client = mock_k8s_client
    notfound_exception = ApiException("NotFound")
    notfound_exception.status = 404
    manager.k8s_client.create_namespaced_secret.side_effect = notfound_exception
    secret_def = {
        "namespace": "default",
        "secret_name": "my-secret",
        "read_type": "SECRET",
        "read_key": "config.json",
    }
    result = create_k8s_secret(manager, secret_def, "secret-value")
    assert result["status"] == "failure"
    assert result["verb"] == "CREATE"
    assert result["source"] == "KUBERNETES"


# --- read_k8s_secret ---
@patch("secretmanager._k8s_ops.crypto_utils.decode_data", return_value="decoded-value")
def test_read_k8s_secret_single_key(mock_decode):
    mock_k8s_client = MagicMock()
    manager = SecretManager()
    manager.k8s_client = mock_k8s_client
    mock_k8s_client.read_namespaced_secret.return_value.data = {
        "config.json": "ZW5jb2RlZA=="
    }
    secret_def = {
        "namespace": "default",
        "secret_name": "my-secret",
        "read_type": "SECRET",
        "read_key": "config.json",
    }
    result = read_k8s_secret(manager, secret_def)
    assert result["status"] == "success"
    assert result["verb"] == "READ"
    assert result["source"] == "KUBERNETES"
    assert result["data"] == "decoded-value"


@patch("secretmanager._k8s_ops.crypto_utils.decode_data", return_value="decoded-value")
def test_read_k8s_secret_all_keys(mock_decode):
    mock_k8s_client = MagicMock()
    manager = SecretManager()
    manager.k8s_client = mock_k8s_client
    mock_k8s_client.read_namespaced_secret.return_value.data = {
        "config.json": "ZW5jb2RlZA==",
        "token.txt": "ZW5jb2RlZA==",
    }
    secret_def = {
        "namespace": "default",
        "secret_name": "my-secret",
        "read_type": "SECRET",
        "read_key": None,  # Read all keys
    }
    result = read_k8s_secret(manager, secret_def)
    assert result["data"] == {
        "config.json": "decoded-value",
        "token.txt": "decoded-value",
    }


def test_read_k8s_config_map():
    mock_k8s_client = MagicMock()
    manager = SecretManager()
    manager.k8s_client = mock_k8s_client
    mock_k8s_client.read_namespaced_config_map.return_value.data = {
        "config.json": "raw-value"
    }
    secret_def = {
        "namespace": "default",
        "secret_name": "my-configmap",
        "read_type": "CONFIG_MAP",
        "read_key": None,  # Read all keys
    }
    result = read_k8s_secret(manager, secret_def)
    assert result["data"] == {"config.json": "raw-value"}


@patch(
    "secretmanager._k8s_ops.client.CoreV1Api.read_namespaced_secret",
    side_effect=client.exceptions.ApiException("API failure"),
)
def test_read_k8s_secret_api_exception(mock_read):
    manager = SecretManager()
    manager.k8s_client = client.CoreV1Api()

    secret_def = {
        "read_type": "SECRET",
        "secret_name": "my-secret",
        "namespace": "default",
    }

    result = read_k8s_secret(manager, secret_def)
    assert result["status"] == "failure"
    assert "API failure" in result["error"]


@patch("secretmanager._k8s_ops.client.CoreV1Api.read_namespaced_secret")
def test_read_k8s_secret_key_error(mock_read):
    mock_read.return_value.data = {"other_key": "c2VjcmV0"}  # base64 for 'secret'
    manager = SecretManager()
    manager.k8s_client = client.CoreV1Api()

    secret_def = {
        "read_type": "SECRET",
        "secret_name": "my-secret",
        "namespace": "default",
        "read_key": "missing_key",
    }

    result = read_k8s_secret(manager, secret_def)
    assert result["status"] == "failure"
    assert "not found in the secret" in result["error"]


@patch(
    "secretmanager._k8s_ops.client.CoreV1Api.read_namespaced_config_map",
    side_effect=Exception("Unexpected error"),
)
def test_read_k8s_secret_generic_exception(mock_read):
    manager = SecretManager()
    manager.k8s_client = client.CoreV1Api()

    secret_def = {
        "read_type": "CONFIG_MAP",
        "secret_name": "my-config",
        "namespace": "default",
    }

    result = read_k8s_secret(manager, secret_def)
    assert result["status"] == "failure"
    assert "Unexpected error" in result["error"]


# --- logout_k8s ---
# @patch("secretmanager._k8s_ops.client.CoreV1Api.delete_namespaced_service_account_token")
def test_logout_k8s():
    manager = SecretManager()
    manager.k8s_client = client.CoreV1Api()

    result = logout_k8s(manager)
    assert result["status"] == "success"
    assert result["verb"] == "LOGOUT"
    assert result["source"] == "KUBERNETES"
