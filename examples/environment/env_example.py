
from secretmanager import SecretManager

log_level = "INFO"
secretcfg = {
    "SOURCE": "ENVIRONMENT"
}

sm = SecretManager(secretcfg, log_level)

secretdef = {
    "env_def_file": 'examples/environment/env_definition.json',
    "env_file": 'examples/environment/env.env',
    "definition_type": 'JSON'
}

secrets = sm.read_secrets(secretdef)

print("JSON Definition:")
for key in secrets:
    print(f"{key}: {secrets[key]}")

secretdef = {
    "env_def_file": 'examples/environment/env_definition.yaml',
    "env_file": 'examples/environment/env.env',
    "definition_type": 'YAML'
}

secrets = sm.read_secrets(secretdef)

print("\nYAML Definition:")
for key in secrets:
    print(f"{key}: {secrets[key]}")
