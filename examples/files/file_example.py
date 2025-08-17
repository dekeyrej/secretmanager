from secretmanager.manager import SecretManager

log_level = "INFO"
secretcfg = {
    "SOURCE": "FILE"
}

sm = SecretManager(secretcfg, log_level)

secret_def = {
    "file_name": 'examples/files/file.json',
    "file_type": 'JSON'
}

jsreturn = sm.execute(secretcfg.get("SOURCE"), "READ", sm, secret_def)
if not jsreturn.get("status") == "success":
    print(f"Error reading secrets: {jsreturn.get('error', 'Unknown error')}")
    exit(1)
jssecrets = jsreturn.get("data", {})

print("JSON Secrets:")
for key in jssecrets:
    print(f"{key}: {jssecrets[key]}")

secret_def = {
    "file_name": 'examples/files/file.yaml',
    "file_type": 'YAML'
}

print("\nYAML Secrets:")
ymreturn = sm.execute(secretcfg.get("SOURCE"), "READ", sm, secret_def)
if not ymreturn.get("status") == "success":
    print(f"Error reading secrets: {ymreturn.get('error', 'Unknown error')}")
    exit(1)
ymsecrets = ymreturn.get("data", {})
for key in ymsecrets:
    print(f"{key}: {ymsecrets[key]}")