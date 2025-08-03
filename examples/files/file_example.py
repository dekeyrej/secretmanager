from secretmanager import SecretManager

log_level = "INFO"
secretcfg = {
    "SOURCE": "FILE"
}

sm = SecretManager(secretcfg, log_level)

secret_def = {
    "file_name": 'examples/files/file.json',
    "file_type": 'JSON'
}

jssecrets = sm.read_secrets(secret_def)

print("JSON Secrets:")
for key in jssecrets:
    print(f"{key}: {jssecrets[key]}")

secret_def = {
    "file_name": 'examples/files/file.yaml',
    "file_type": 'YAML'
}

print("\nYAML Secrets:")
ymsecrets = sm.read_secrets(secret_def)
for key in ymsecrets:
    print(f"{key}: {ymsecrets[key]}")