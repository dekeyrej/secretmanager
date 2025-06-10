import re
import certifi

python_cacert = certifi.where()
with open(python_cacert, "r") as f:
    cacert = f.read()

with open("examples/vault_ssl_support/ca.crt", "r") as f:
    local_cacert = f.read()
pattern = r"{}".format(re.escape(local_cacert.strip()))

if re.search(pattern, cacert):
    print("CA certificate already exists in the system CA bundle.")
else:
    with open(python_cacert, "a") as f:
        f.write("\n" + local_cacert)
    print("CA certificate appended to the system CA bundle.")
    print("Please restart your application to use the updated CA bundle.")
    print("You can also set the 'verify' parameter to 'ca.crt' in your Vault configuration to use this CA certificate.")