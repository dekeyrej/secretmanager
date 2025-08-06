import yaml
import tempfile
import pytest
import secretmanager._source_loader as source_loader
from secretmanager._source_loader import (
    read_data_from_file,
    read_secrets_from_env,
    load_json_secrets,
    load_yaml_secrets,
    read_secrets_from_file,
    create_secrets_file,
    init_file,
    init_environment,
    logout_file,
    logout_environment,
)
from unittest.mock import MagicMock


# --- read_data_from_file ---
def test_read_data_from_file_success():
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write("secret-content")
        tmp_path = tmp.name
    assert read_data_from_file(tmp_path) == "secret-content"


def test_read_data_from_file_not_found():
    with pytest.raises(FileNotFoundError):
        read_data_from_file("nonexistent_file.txt")


# --- load_json_secrets ---
def test_load_json_secrets_valid():
    raw = '{"key": "value"}'
    assert load_json_secrets(raw) == {"key": "value"}


def test_load_json_secrets_invalid():
    raw = '{"key": "value"'  # Missing closing brace
    assert load_json_secrets(raw) == {}


# --- load_yaml_secrets ---
def test_load_yaml_secrets_valid():
    raw = "key: value"
    assert load_yaml_secrets(raw) == {"key": "value"}


def test_load_yaml_secrets_invalid():
    raw = "key: value: another"  # Invalid YAML
    assert load_yaml_secrets(raw) == {}


# --- read_secrets_from_file ---
def test_read_secrets_from_file_json():
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write('{"api_key": "12345"}')
        tmp_path = tmp.name
    secret_def = {"file_name": tmp_path, "file_type": "JSON"}
    assert read_secrets_from_file(secret_def)["data"] == {"api_key": "12345"}


def test_read_secrets_from_file_yaml():
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write("api_key: 12345")
        tmp_path = tmp.name
    secret_def = {"file_name": tmp_path, "file_type": "YAML"}
    assert read_secrets_from_file(secret_def)["data"] == {"api_key": 12345}


def test_read_secrets_from_file_bob():
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write("api_key: 12345")
        tmp_path = tmp.name
    secret_def = {"file_name": tmp_path, "file_type": "BOB"}
    result = read_secrets_from_file(secret_def)
    assert result["verb"] == "READ"
    assert result["source"] == "FILE"
    assert result["data"] == {}


def test_read_secrets_from_file_json_no_file():
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        tmp.write('{"api_key": "12345"}')
    secret_def = {"file_name": "no_file.json", "file_type": "JSON"}
    result = read_secrets_from_file(secret_def)
    assert result["status"] == "failure"
    assert result["verb"] == "READ"
    assert result["source"] == "FILE"
    assert "error" in result


def test_read_secrets_from_file_missing_key():
    result = read_secrets_from_file({})  # Missing 'file_name' and 'file_type'
    assert result["status"] == "failure"
    assert result["verb"] == "READ"
    assert result["source"] == "FILE"
    assert "error" in result


# --- create_secrets_file ---
def test_create_secrets_file_json(tmp_path):
    import json

    file_path = tmp_path / "secrets.json"
    secret_def = {"file_type": "JSON", "file_name": str(file_path)}
    data = {"api_key": "12345", "token": "abcdef"}

    result = create_secrets_file(secret_def, data)

    assert result["status"] == "success"
    assert result["verb"] == "CREATE"
    assert result["source"] == "FILE"
    assert result["data"] == data

    # Verify file contents
    written = json.loads(file_path.read_text())
    assert written == data


def test_create_secrets_file_yaml(tmp_path):
    import yaml

    file_path = tmp_path / "secrets.yaml"
    secret_def = {"file_type": "YAML", "file_name": str(file_path)}
    data = {"username": "frodo", "password": "shire"}

    result = create_secrets_file(secret_def, data)

    assert result["status"] == "success"
    assert result["data"] == data

    # Verify YAML structure
    written = yaml.safe_load(file_path.read_text())
    assert written == data


def test_create_secrets_file_unknown_type(tmp_path):
    file_path = tmp_path / "secrets.txt"
    secret_def = {"file_type": "TOML", "file_name": str(file_path)}  # unsupported
    data = {"key": "value"}

    result = create_secrets_file(secret_def, data)

    assert result["status"] == "failure"
    assert "Unknown secret type" in result["error"]
    assert not file_path.exists()


def test_create_secrets_file_write_error(monkeypatch):
    secret_def = {
        "file_type": "JSON",
        "file_name": "/root/forbidden.json",  # likely unwritable
    }
    data = {"key": "value"}

    result = create_secrets_file(secret_def, data)

    assert result["status"] == "failure"
    assert "Permission denied" in result["error"]


# --- read_secrets_from_env ---
def test_read_secrets_from_env_json(monkeypatch, tmp_path):
    monkeypatch.setenv("MY_SECRET", "env-value")
    env_def_file = tmp_path / "env_def.json"
    env_def_file.write_text('{"api_key": "MY_SECRET"}')
    secret_def = {
        "env_file": None,
        "definition_type": "JSON",
        "env_def_file": str(env_def_file),
    }
    result = read_secrets_from_env(secret_def)
    assert result["data"] == {"api_key": "env-value"}


def test_read_secrets_from_env_bad_json(monkeypatch, tmp_path):
    monkeypatch.setenv("MY_SECRET", "env-value")
    env_def_file = tmp_path / "env_def.json"
    env_def_file.write_text('{"api_key"; "MY_SECRET"}')
    secret_def = {
        "env_file": None,
        "definition_type": "JSON",
        "env_def_file": str(env_def_file),
    }
    result = read_secrets_from_env(secret_def)
    assert result["status"] == "failure"
    assert result["verb"] == "READ"
    assert result["source"] == "ENVIRONMENT"
    assert "Invalid JSON format" in result["error"]


def test_read_secrets_from_env_json_env_file(monkeypatch, tmp_path):
    env_def_file = tmp_path / "env_def.json"
    env_def_file.write_text('{"api_key": "MY_SECRET"}')
    env_file = tmp_path / "env_file.env"
    env_file.write_text("MY_SECRET=env-value")
    secret_def = {
        "env_file": str(env_file),
        "definition_type": "JSON",
        "env_def_file": str(env_def_file),
    }
    result = read_secrets_from_env(secret_def)
    assert result["data"] == {"api_key": "env-value"}


def test_read_secrets_from_env_yaml(monkeypatch, tmp_path):
    monkeypatch.setenv("MY_SECRET", "env-value")
    env_def_file = tmp_path / "env_def.yaml"
    env_def_file.write_text("api_key: MY_SECRET")
    secret_def = {
        "env_file": None,
        "definition_type": "YAML",
        "env_def_file": str(env_def_file),
    }
    result = read_secrets_from_env(secret_def)
    assert result["data"] == {"api_key": "env-value"}


def test_read_secrets_from_env_bad_yaml(monkeypatch, tmp_path):
    monkeypatch.setenv("MY_SECRET", "env-value")
    monkeypatch.setattr(
        source_loader.yaml,
        "safe_load",
        lambda _: (_ for _ in ()).throw(yaml.YAMLError("Invalid YAML")),
    )
    env_def_file = tmp_path / "env_def.yaml"
    env_def_file.write_text("api_key**MY_SECRET")
    secret_def = {
        "env_file": None,
        "definition_type": "YAML",
        "env_def_file": str(env_def_file),
    }
    result = read_secrets_from_env(secret_def)
    assert result["status"] == "failure"
    assert result["verb"] == "READ"
    assert result["source"] == "ENVIRONMENT"
    assert "data" not in result


def test_read_secrets_from_env_missing_env_var(tmp_path):
    env_def_file = tmp_path / "env_def.json"
    env_def_file.write_text('{"api_key": "MISSING_VAR"}')
    secret_def = {
        "env_file": None,
        "definition_type": "JSON",
        "env_def_file": str(env_def_file),
    }
    result = read_secrets_from_env(secret_def)
    assert result["status"] == "failure"
    assert result["verb"] == "READ"
    assert result["source"] == "ENVIRONMENT"
    assert "error" in result


# --- iniit/logout -- functions ---
def test_init_file_success():
    mock_manager = (
        MagicMock()
    )  # Even though it's unused, keeps the interface consistent
    result = init_file(mock_manager)

    assert result == {"status": "success", "verb": "INIT", "source": "FILE"}


def test_init_environment_success():
    mock_manager = (
        MagicMock()
    )  # Even though it's unused, keeps the interface consistent
    result = init_environment(mock_manager)

    assert result == {"status": "success", "verb": "INIT", "source": "ENVIRONMENT"}


def test_logout_file_success():
    mock_manager = (
        MagicMock()
    )  # Even though it's unused, keeps the interface consistent
    result = logout_file(mock_manager)

    assert result == {"status": "success", "verb": "LOGOUT", "source": "FILE"}


def test_logout_environment_success():
    mock_manager = (
        MagicMock()
    )  # Even though it's unused, keeps the interface consistent
    result = logout_environment(mock_manager)

    assert result == {"status": "success", "verb": "LOGOUT", "source": "ENVIRONMENT"}
