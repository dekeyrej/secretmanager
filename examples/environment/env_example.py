import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../secretmanager')))

from secretmanager import SecretManager

log_level = "INFO"
config = {
    "SOURCE": "ENVIRONMENT"
}
environment_definition = 'examples/environment/env_definition.json'
definition_type        = 'JSON'
environment_file       = 'examples/environment/env.env'


sm = SecretManager(config, log_level)
secrets = sm.read_secrets(environment_definition, env_file=environment_file, definition_type=definition_type)

print("JSON Definition:")
for key in secrets:
    print(f"{key}: {secrets[key]}")

environment_definition = 'examples/environment/env_definition.yaml'
definition_type        = 'YAML'
environment_file       = 'examples/environment/env.env'


secrets = sm.read_secrets(environment_definition, env_file=environment_file, definition_type=definition_type)
print("\nYAML Definition:")
for key in secrets:
    print(f"{key}: {secrets[key]}")
