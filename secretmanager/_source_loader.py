import json
import yaml
import logging

from secretmanager.manager import SecretManager

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

# the following methods handle reading text data from a file,
# well suited for reading a secrets file,
# for encoding/encryption/storage in a kube secret.


def read_data_from_file(file_path: str) -> str:
    try:
        with open(file_path, "r") as f:
            logger.debug(f"Reading data from file: {file_path}")
            retstr = f.read()
            return retstr
    except FileNotFoundError:
        raise FileNotFoundError(f"File '{file_path}' not found.")
    # except IOError as e:
    #     raise IOError(f"Error reading file '{file_path}': {e}")


# SOURCE="ENVIRONMENT"
def read_secrets_from_env(manager: SecretManager, secret_def: dict) -> dict:
    """Reads secrets from environment variables or a .env file"""
    import os
    from dotenv import load_dotenv

    try:
        if secret_def["env_file"]:
            logger.debug(
                f"Loading environment variables from file: {secret_def['env_file']}"
            )
            load_dotenv(secret_def["env_file"])

        secrets = {}
        if secret_def["definition_type"] == "JSON":
            try:
                logger.debug(
                    f"Loading environment definition from JSON file: {secret_def['env_def_file']}"
                )
                env_def = json.loads(read_data_from_file(secret_def["env_def_file"]))
            except json.JSONDecodeError:
                raise ValueError(
                    f"Invalid JSON format in '{secret_def['env_def_file']}'."
                )
        elif secret_def["definition_type"] == "YAML":
            try:
                logger.debug(
                    f"Loading environment definition from YAML file: {secret_def['env_def_file']}"
                )
                env_def = yaml.safe_load(
                    read_data_from_file(secret_def["env_def_file"])
                )
            except yaml.YAMLError:
                raise ValueError(
                    f"Invalid YAML format in '{secret_def['env_def_file']}'."
                )

        for key, env_var in env_def.items():
            logger.debug(f"Retrieving environment variable: {env_var}")
            if env_var not in os.environ:
                raise KeyError(f"Environment variable '{env_var}' is not set.")
            secrets[key] = os.getenv(env_var)

        return {
            "status": "success",
            "verb": "READ",
            "source": "ENVIRONMENT",
            "data": secrets,
        }
    except KeyError as e:
        logger.error(f"Missing key in secret definition: {e}")
        return {
            "status": "failure",
            "verb": "READ",
            "source": "ENVIRONMENT",
            "error": str(e),
        }
    except Exception as e:
        logger.error(f"Error reading secrets from environment: {e}")
        return {
            "status": "failure",
            "verb": "READ",
            "source": "ENVIRONMENT",
            "error": str(e),
        }


# The following methods handle loading secrets from JSON or YAML strings.
def load_json_secrets(rawsecrets: str) -> dict:
    """Load secrets from the specified file"""
    try:
        return json.loads(rawsecrets)
    except json.JSONDecodeError:
        return {}


def load_yaml_secrets(rawsecrets: str) -> dict:
    """Load secrets from the specified file"""
    try:
        return yaml.safe_load(rawsecrets)
    except yaml.YAMLError:
        return {}


# SOURCE="FILE"
def read_secrets_from_file(manager: SecretManager, secret_def: dict) -> dict:
    """Return the loaded file secrets"""
    try:
        rawsecrets = read_data_from_file(secret_def["file_name"])
        if secret_def["file_type"] == "JSON":
            retval = load_json_secrets(rawsecrets)
        elif secret_def["file_type"] == "YAML":
            retval = load_yaml_secrets(rawsecrets)
        else:
            print(f"Unknown secret type '{secret_def['file_type']}'.")
            retval = {}
    except KeyError as e:
        logger.error(f"Missing key in secret definition: {e}")
        return {"status": "failure", "verb": "READ", "source": "FILE", "error": str(e)}
    except Exception as e:
        logger.error(f"Error reading secrets from file: {e}")
        return {"status": "failure", "verb": "READ", "source": "FILE", "error": str(e)}
    else:
        return {"status": "success", "verb": "READ", "source": "FILE", "data": retval}


# SOURCE="FILE"
def create_secrets_file(manager: SecretManager, secret_def: dict, data: dict) -> dict:
    """Create a secrets file from the provided data"""
    if secret_def["file_type"] == "JSON":
        contents = json.dumps(data, indent=2)
    elif secret_def["file_type"] == "YAML":
        contents = yaml.dump(data, default_flow_style=False, sort_keys=False)
    else:
        logger.error(f"Unknown secret type '{secret_def['file_type']}'.")
        return {
            "status": "failure",
            "verb": "CREATE",
            "source": "FILE",
            "error": f"Unknown secret type '{secret_def['file_type']}'.",
        }

    try:
        with open(secret_def["file_name"], "w") as f:
            f.write(contents)
    except Exception as e:
        logger.error(f"Error writing secrets to file: {e}")
        return {
            "status": "failure",
            "verb": "CREATE",
            "source": "FILE",
            "error": str(e),
        }
    else:
        return {"status": "success", "verb": "CREATE", "source": "FILE", "data": data}


def init_file(manager: SecretManager) -> dict:
    logger.info("File source initialized successfully.")
    return {"status": "success", "verb": "INIT", "source": "FILE"}


def init_environment(manager: SecretManager) -> dict:
    logger.info("Environment source initialized successfully.")
    return {"status": "success", "verb": "INIT", "source": "ENVIRONMENT"}


def logout_file(manager: SecretManager) -> dict:
    logger.info("File source reset successfully.")
    return {"status": "success", "verb": "LOGOUT", "source": "FILE"}


def logout_environment(manager: SecretManager) -> dict:
    logger.info("Environment source reset successfully.")
    return {"status": "success", "verb": "LOGOUT", "source": "ENVIRONMENT"}
