import pytest
from copy import deepcopy

# Import the verb we want to test
# import secretmanager._vault_ops as vops
from secretmanager._kubevault_ops import (
    init_kubevault,
    reauthenticate_vault_via_kubernetes,
)


# 🔧 Patch external dependencies used by init_kubevault
@pytest.fixture(autouse=True)
# @pytest.fixture
def patch_kubevault(monkeypatch):
    class MockVaultClient:
        def __init__(self):
            self.token = None

        def is_authenticated(self):
            return False

    monkeypatch.setattr(
        "secretmanager._kubevault_ops.connect_to_k8s", lambda m: "k8s_client"
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.connect_to_vault",
        lambda url, ca: MockVaultClient(),
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt-token"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: "vault-token",
    )


# 🧰 Patch the registry before SecretManager is created
@pytest.fixture
def manager(monkeypatch):
    from secretmanager import secretregistry
    from secretmanager.manager import SecretManager

    # Deepcopy to avoid test pollution
    patched_registry = deepcopy(secretregistry.SECRET_VERB_REGISTRY)
    patched_registry["KUBEVAULT"]["INIT"] = init_kubevault

    # Patch the global registry
    monkeypatch.setattr(secretregistry, "SECRET_VERB_REGISTRY", patched_registry)

    config = {
        "vault_url": "http://vault",
        "kube_config": None,
        "ca_cert": True,
        "service_account": "default",
        "namespace": "default",
        "role": "my-role",
        "SOURCE": "KUBEVAULT",
    }

    return SecretManager(config)


# ✅ Actual test


def test_kubevault_init_success(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.connect_to_k8s", lambda m: "k8s_client"
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.connect_to_vault",
        lambda url, ca: type(
            "VaultClient", (), {"is_authenticated": lambda self: True, "token": None}
        )(),
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt-token"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: "vault-token",
    )

    result = manager.execute("KUBEVAULT", "INIT", manager)
    assert result["status"] == "success"


def test_kubevault_init_no_jwt(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.connect_to_k8s", lambda m: "k8s_client"
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.connect_to_vault",
        lambda url, ca: type(
            "VaultClient", (), {"is_authenticated": lambda self: False, "token": None}
        )(),
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": None},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: "vault-token",
    )

    result = manager.execute("KUBEVAULT", "INIT", manager)
    assert result["status"] == "failure"


def test_kubevault_init_hvac_reauth_success(monkeypatch, manager):
    class ReauthVaultClient:
        def __init__(self):
            self.token = None
            self._authenticated = False

        def is_authenticated(self):
            return self._authenticated

    vault_client = ReauthVaultClient()

    def mock_authenticate(client, role, jwt):
        client.token = "vault-token"
        client._authenticated = True
        return client.token

    # Override autouse fixture's patch
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.connect_to_vault", lambda url, ca: vault_client
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        mock_authenticate,
    )

    result = manager.execute("KUBEVAULT", "INIT", manager)
    assert result["status"] == "success"


def test_reauthenticate_vault_success(monkeypatch, manager):
    class ReauthClient:
        def __init__(self):
            self.token = None
            self._authenticated = False

        def is_authenticated(self):
            return self._authenticated

    client = ReauthClient()
    manager.hvac_client = client
    manager.k8s_client = "mock-k8s"

    def mock_authenticate(c, role, jwt):
        c.token = "vault-token"
        c._authenticated = True
        return c.token

    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt-token"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        mock_authenticate,
    )

    result = reauthenticate_vault_via_kubernetes(manager)
    assert result is True


def test_reauthenticate_vault_via_kubernetes_no_jwt(monkeypatch, manager):
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: False, "token": None}
    )()
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": None},
    )
    result = reauthenticate_vault_via_kubernetes(manager)
    assert not result


def test_reauthenticate_vault_via_kubernetes_no_token(monkeypatch, manager):
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: False, "token": None}
    )()
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt-token"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: None,
    )
    result = reauthenticate_vault_via_kubernetes(manager)
    assert not result


def test_kubevault_read_success(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.read_k8s_secret",
        lambda m, sd: {"data": "ciphertext"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.decrypt_data_with_vault",
        lambda client, key, data: '{"foo": "bar"}',
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.load_json_secrets", lambda data: {"foo": "bar"}
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: "vault-token",
    )
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: True}
    )()
    manager.k8s_client = "k8s_client"

    secret_def = {
        "secret_name": "my-secret",
        "namespace": "default",
        "transit_key": "my-key",
        "read_key": "secrets.json",
        "read_type": "SECRET",
    }
    result = manager.execute("KUBEVAULT", "READ", manager, secret_def)
    assert result["status"] == "success"
    assert result["data"]["foo"] == "bar"


def test_kubevault_read_failure_with_reauth_failure(monkeypatch, manager):
    # Simulate a Vault client that starts unauthenticated, then becomes authenticated
    class VaultClient:
        def __init__(self):
            self.token = None
            self._authenticated = False

        def is_authenticated(self):
            return self._authenticated

    vault_client = VaultClient()

    # Simulate successful reauthentication
    def mock_authenticate(client, role, jwt):
        client.token = "vault-token"
        client._authenticated = False
        return client.token

    monkeypatch.setattr(
        "secretmanager._kubevault_ops.read_k8s_secret",
        lambda m, sd: {"data": "ciphertext"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.decrypt_data_with_vault",
        lambda client, key, data: '{"foo": "bar"}',
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.load_json_secrets", lambda data: {"foo": "bar"}
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        mock_authenticate,
    )

    manager.hvac_client = vault_client
    manager.k8s_client = "k8s_client"

    secret_def = {
        "secret_name": "my-secret",
        "namespace": "default",
        "transit_key": "my-key",
        "read_key": "secrets.json",
        "read_type": "SECRET",
    }

    result = manager.execute("KUBEVAULT", "READ", manager, secret_def)

    assert result["status"] == "failure"


def test_kubevault_read_failure1(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.read_k8s_secret", lambda m, sd: {"data": -1}
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.decrypt_data_with_vault",
        lambda client, key, data: '{"foo": "bar"}',
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.load_json_secrets", lambda data: {"foo": "bar"}
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: "vault-token",
    )
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: True}
    )()
    manager.k8s_client = "k8s_client"

    secret_def = {
        "secret_name": "my-secret",
        "namespace": "default",
        "transit_key": "my-key",
        "read_key": "secrets.json",
        "read_type": "SECRET",
    }
    result = manager.execute("KUBEVAULT", "READ", manager, secret_def)
    assert result["status"] == "failure"


def test_kubevault_read_failure2(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.read_k8s_secret",
        lambda m, sd: {"data": "ciphertext"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.decrypt_data_with_vault",
        lambda client, key, data: None,
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.load_json_secrets", lambda data: {"foo": "bar"}
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: "vault-token",
    )
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: True}
    )()
    manager.k8s_client = "k8s_client"

    secret_def = {
        "secret_name": "my-secret",
        "namespace": "default",
        "read_key": "secrets.json",
        "read_type": "SECRET",
    }
    result = manager.execute("KUBEVAULT", "READ", manager, secret_def)
    assert result["status"] == "failure"


def test_kubevault_read_failure3(monkeypatch, manager):
    # Simulate a Vault client that starts unauthenticated, then becomes authenticated
    class VaultClient:
        def __init__(self):
            self.token = None
            self._authenticated = False

        def is_authenticated(self):
            return self._authenticated

    vault_client = VaultClient()

    # Simulate successful reauthentication
    def mock_authenticate(client, role, jwt):
        client.token = "vault-token"
        client._authenticated = True
        return client.token

    monkeypatch.setattr(
        "secretmanager._kubevault_ops.read_k8s_secret",
        lambda m, sd: {"data": "ciphertext"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.decrypt_data_with_vault",
        lambda client, key, data: None,
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.load_json_secrets", lambda data: {"foo": "bar"}
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        mock_authenticate,
    )

    manager.hvac_client = vault_client
    manager.k8s_client = "k8s_client"

    secret_def = {
        "secret_name": "my-secret",
        "namespace": "default",
        "transit_key": "my-key",
        "read_key": "secrets.json",
        "read_type": "SECRET",
    }

    result = manager.execute("KUBEVAULT", "READ", manager, secret_def)

    assert result["status"] == "failure"
    # assert result["data"]["foo"] == "bar"


def test_kubevault_create_success(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.encrypt_data_with_vault",
        lambda client, key, data: "encrypted",
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.create_k8s_secret", lambda m, sd, ed: None
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: "vault-token",
    )
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: True}
    )()
    manager.k8s_client = "k8s_client"

    secret_def = {
        "secret_name": "my-secret",
        "namespace": "default",
        "transit_key": "my-key",
        "read_key": "secrets.json",
        "read_type": "SECRET",
    }
    result = manager.execute("KUBEVAULT", "CREATE", manager, secret_def, "plaintext")
    assert result["status"] == "success"


def test_kubevault_create_failure_no_auth(monkeypatch, manager):
    # Simulate a Vault client that starts unauthenticated, then becomes authenticated
    class VaultClient:
        def __init__(self):
            self.token = None
            self._authenticated = False

        def is_authenticated(self):
            return self._authenticated

    vault_client = VaultClient()

    # Simulate successful reauthentication
    def mock_authenticate(client, role, jwt):
        client.token = "vault-token"
        client._authenticated = True
        return client.token

    monkeypatch.setattr(
        "secretmanager._kubevault_ops.encrypt_data_with_vault",
        lambda client, key, data: "encrypted",
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.create_k8s_secret", lambda m, sd, ed: None
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        mock_authenticate,
    )

    manager.hvac_client = vault_client
    manager.k8s_client = "k8s_client"

    secret_def = {
        "secret_name": "my-secret",
        "namespace": "default",
        "transit_key": "my-key",
        "read_key": "secrets.json",
        "read_type": "SECRET",
    }

    result = manager.execute("KUBEVAULT", "CREATE", manager, secret_def, "plaintext")
    assert result["status"] == "success"


def test_kubevault_create_failure_no_auth_no_reauth(monkeypatch, manager):
    # Simulate a Vault client that starts unauthenticated, then becomes authenticated
    class VaultClient:
        def __init__(self):
            self.token = None
            self._authenticated = False

        def is_authenticated(self):
            return self._authenticated

    vault_client = VaultClient()

    # Simulate successful reauthentication
    def mock_authenticate(client, role, jwt):
        client.token = "vault-token"
        client._authenticated = False
        return client.token

    monkeypatch.setattr(
        "secretmanager._kubevault_ops.encrypt_data_with_vault",
        lambda client, key, data: "encrypted",
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.create_k8s_secret", lambda m, sd, ed: None
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        mock_authenticate,
    )

    manager.hvac_client = vault_client
    manager.k8s_client = "k8s_client"

    secret_def = {
        "secret_name": "my-secret",
        "namespace": "default",
        "transit_key": "my-key",
        "read_key": "secrets.json",
        "read_type": "SECRET",
    }

    result = manager.execute("KUBEVAULT", "CREATE", manager, secret_def, "plaintext")
    assert result["status"] == "failure"


def test_kubevault_create_no_transit(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.encrypt_data_with_vault",
        lambda client, key, data: "encrypted",
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.create_k8s_secret", lambda m, sd, ed: None
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: "vault-token",
    )
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: True}
    )()
    manager.k8s_client = "k8s_client"

    secret_def = {
        "secret_name": "my-secret",
        "namespace": "default",
        "read_key": "secrets.json",
        "read_type": "SECRET",
    }
    result = manager.execute("KUBEVAULT", "CREATE", manager, secret_def, "plaintext")
    assert result["status"] == "failure"


def test_kubevault_create_no_encrypt(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.encrypt_data_with_vault",
        lambda client, key, data: None,
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.create_k8s_secret", lambda m, sd, ed: None
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: "vault-token",
    )
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: True}
    )()
    manager.k8s_client = "k8s_client"

    secret_def = {
        "secret_name": "my-secret",
        "namespace": "default",
        "transit_key": "my-key",
        "read_key": "secrets.json",
        "read_type": "SECRET",
    }
    result = manager.execute("KUBEVAULT", "CREATE", manager, secret_def, "plaintext")
    assert result["status"] == "failure"


def test_kubevault_rotate_success(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._rotate_vault_key",
        lambda client, key: {"status": "success"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: "vault-token",
    )
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: True}
    )()
    manager.k8s_client = "k8s_client"

    result = manager.execute("KUBEVAULT", "ROTATE", manager, "my-key")
    assert result["status"] == "success"


def test_kubevault_rotate_no_auth(monkeypatch, manager):
    # Simulate a Vault client that starts unauthenticated, then becomes authenticated
    class VaultClient:
        def __init__(self):
            self.token = None
            self._authenticated = False

        def is_authenticated(self):
            return self._authenticated

    vault_client = VaultClient()

    # Simulate successful reauthentication
    def mock_authenticate(client, role, jwt):
        client.token = "vault-token"
        client._authenticated = True
        return client.token

    monkeypatch.setattr(
        "secretmanager._kubevault_ops._rotate_vault_key",
        lambda client, key: {"status": "success"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        mock_authenticate,
    )

    manager.hvac_client = vault_client
    manager.k8s_client = "k8s_client"

    result = manager.execute("KUBEVAULT", "ROTATE", manager, "my-key")
    assert result["status"] == "success"


def test_kubevault_rotate_no_auth_no_reauth(monkeypatch, manager):
    # Simulate a Vault client that starts unauthenticated, then becomes authenticated
    class VaultClient:
        def __init__(self):
            self.token = None
            self._authenticated = False

        def is_authenticated(self):
            return self._authenticated

    vault_client = VaultClient()

    # Simulate successful reauthentication
    def mock_authenticate(client, role, jwt):
        client.token = "vault-token"
        client._authenticated = False
        return client.token

    monkeypatch.setattr(
        "secretmanager._kubevault_ops._rotate_vault_key",
        lambda client, key: {"status": "success"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        mock_authenticate,
    )

    manager.hvac_client = vault_client
    manager.k8s_client = "k8s_client"

    result = manager.execute("KUBEVAULT", "ROTATE", manager, "my-key")
    assert result["status"] == "failure"


def test_kubevault_rotate_no_rotate(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._rotate_vault_key",
        lambda client, key: {"status": "failure"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._get_k8s_service_account_token",
        lambda c, sa, ns: {"data": "jwt"},
    )
    monkeypatch.setattr(
        "secretmanager._kubevault_ops._authenticate_vault_via_kubernetes",
        lambda c, r, j: "vault-token",
    )
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: True}
    )()
    manager.k8s_client = "k8s_client"

    result = manager.execute("KUBEVAULT", "ROTATE", manager, "my-key")
    assert result["status"] == "failure"


def test_kubevault_logout(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.logout_vault", lambda client: None
    )
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: True}
    )()
    manager.k8s_client = "k8s_client"

    result = manager.execute("KUBEVAULT", "LOGOUT", manager)
    assert result["status"] == "success"
    assert manager.hvac_client is None
    assert manager.k8s_client is None


def test_kubevault_logout_no_auth(monkeypatch, manager):
    monkeypatch.setattr(
        "secretmanager._kubevault_ops.logout_vault", lambda client: None
    )
    manager.hvac_client = type(
        "VaultClient", (), {"is_authenticated": lambda self: False}
    )()
    manager.k8s_client = "k8s_client"

    result = manager.execute("KUBEVAULT", "LOGOUT", manager)
    assert result["status"] == "success"
    assert manager.hvac_client is None
    assert manager.k8s_client is None
