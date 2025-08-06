import pytest
from secretmanager.manager import SecretManager


def test_manager_initializes_with_no_config(caplog):
    manager = SecretManager()
    assert manager.config is None
    assert manager.k8s_client is None
    assert manager.hvac_client is None
    assert "No configuration provided" in caplog.text


def test_manager_rejects_invalid_source():
    manager = SecretManager()
    bad_config = {"SOURCE": "INVALID"}
    with pytest.raises(ValueError) as excinfo:
        manager.configure_secret_type(bad_config)
    assert "Invalid configuration source" in str(excinfo.value)


def test_manager_accepts_valid_source(monkeypatch):
    # Patch registry.perform to avoid triggering actual INIT logic
    monkeypatch.setattr(
        "secretmanager.manager.SecretManager.execute",
        lambda self, backend, verb, *args, **kwargs: f"{backend}:{verb}",
    )

    config = {"SOURCE": "FILE"}
    manager = SecretManager(config)
    assert manager.config == config


def test_manager_reconfigures_source(monkeypatch, caplog):
    monkeypatch.setattr(
        "secretmanager.manager.SecretManager.execute",
        lambda self, backend, verb, *args, **kwargs: f"{backend}:{verb}",
    )
    monkeypatch.setattr(
        "secretmanager.verbregistry.VerbRegistry.perform",
        lambda self, backend, verb, *args, **kwargs: f"{backend}:{verb}",
    )

    manager = SecretManager({"SOURCE": "FILE"})
    new_config = {"SOURCE": "ENVIRONMENT"}
    manager.configure_secret_type(new_config)

    assert manager.config == new_config
    assert "Changing configuration source from FILE to ENVIRONMENT" in caplog.text


def test_manager_reconfigures_to_same_source(monkeypatch, caplog):
    monkeypatch.setattr(
        "secretmanager.manager.SecretManager.execute",
        lambda self, backend, verb, *args, **kwargs: f"{backend}:{verb}",
    )
    monkeypatch.setattr(
        "secretmanager.verbregistry.VerbRegistry.perform",
        lambda self, backend, verb, *args, **kwargs: f"{backend}:{verb}",
    )

    manager = SecretManager({"SOURCE": "FILE"})
    new_config = {"SOURCE": "FILE"}
    manager.configure_secret_type(new_config)

    assert manager.config == new_config
    assert "SecretManager already configured with source: FILE" in caplog.text
