from secretmanager.manager import SecretManager

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

jsreturn = sm.execute(secretcfg.get("SOURCE"), "READ", sm, secretdef)
if not jsreturn.get("status") == "success":
    print(f"Error reading secrets: {jsreturn.get('error', 'Unknown error')}")
    exit(1)
jssecrets = jsreturn.get("data", {})

print("JSON Definition:")
for key in jssecrets:
    print(f"{key}: {jssecrets[key]}")

secretdef = {
    "env_def_file": 'examples/environment/env_definition.yaml',
    "env_file": 'examples/environment/env.env',
    "definition_type": 'YAML'
}

ymreturn = sm.execute(secretcfg.get("SOURCE"), "READ", sm, secretdef)
if not ymreturn.get("status") == "success":
    print(f"Error reading secrets: {ymreturn.get('error', 'Unknown error')}")
    exit(1)
ymsecrets = ymreturn.get("data", {})

print("\nYAML Definition:")
for key in ymsecrets:
    print(f"{key}: {ymsecrets[key]}")
