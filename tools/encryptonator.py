import argparse
import json
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
import sys
import os

from secretmanager import SecretManager

parser = argparse.ArgumentParser()
parser.add_argument('--json', help='JSON string to encrypt')
parser.add_argument('--file', help='Path to JSON file')
args = parser.parse_args()

if args.json:
    secrettext = args.json
elif args.file:
    with open(args.file, 'r') as f:
        secrettext = f.read()
else:
    logging.error("No input source specified.")
    sys.exit(1)

try:
    secrets = json.loads(secrettext)
except json.JSONDecodeError as e:
    logging.error(f"Invalid JSON input: {e}")
    sys.exit(1)

with open("secretcfg.json") as f:
    secretcfg = json.loads(f.read())

with open("secretdef.json") as f:
    secretdef = json.loads(f.read())

log_level        = logging.INFO
validate         = os.getenv("VALIDATE", "True").lower() in ("true", "1", "yes")  

sm = SecretManager(secretcfg, log_level)
sm.execute(secretcfg.get("SOURCE"), "CREATE", sm, secretdef, secrettext)

if validate:
    read_result = sm.execute(secretcfg.get("SOURCE"), "READ", sm, secretdef)

    if secrets != read_result.get("data", {}):
        logging.error("Validation failed: secrets do not match.")
        raise ValueError("Validation failed: secrets do not match.")
    else:
        logging.info("Validation successful: secrets match.")
result = sm.execute(secretcfg.get("SOURCE"), "LOGOUT", sm)