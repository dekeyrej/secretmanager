import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../secretmanager')))

from secretmanager import SecretManager

log_level = "INFO"
config = {
    "SOURCE": "FILE"
}

file_name = 'examples/files/file.json'
file_type = 'JSON'

sm = SecretManager(config, log_level)
jssecrets = sm.read_secrets(file_name, secret_type=file_type)

print("JSON Secrets:")
for key in jssecrets:
    print(f"{key}: {jssecrets[key]}")

file_name = 'examples/files/file.yaml'
file_type = 'YAML'

print("\nYAML Secrets:")
ymsecrets = sm.read_secrets(file_name, secret_type=file_type)
for key in ymsecrets:
    print(f"{key}: {ymsecrets[key]}")