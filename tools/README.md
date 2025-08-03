# SecretManager: Secure Secrets for Kubernetes - Leveraging HashiCorp Vault

[![License](https://img.shields.io/github/license/dekeyrej/secretmanger)](https://github.com/dekeyrej/secretmanger/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/dekeyrej/secretmanger)](https://github.com/dekeyrej/secretmanger)

This repository presents a secure approach to managing secrets within your Kubernetes cluster leveraging HashiCorp Vault’s robust capabilities. While this was developed for my homelab cluster; it’s intended to be a solid foundation for implementing a “Secret Zero” strategy – minimizing risk by reducing the attack surface and limiting the exposure of sensitive information.

## 🛠️ Tools Directory

This directory contains operational utilities for managing secrets in Kubernetes using HashiCorp Vault. Each script is designed to be run independently and demonstrates secure practices for encryption, decryption, and key rotation.

These tools are:
- **Runnable**: Designed for direct execution
- **Composable**: Built atop the `secretmanager` module
- **Secure**: Follow ephemeral, least-privilege principles

**Why This Matters: Embracing Secret Zero**

The "Secret Zero" philosophy centers on the principle of minimizing the risk of compromised secrets.  Traditional methods of managing secrets—storing them directly in configuration files, environment variables, or with static keys—present significant vulnerabilities. This project aims to address these concerns by leveraging proven techniques for secure encryption and rotation.

**Key Features & Inspiration from HashiCorp Vault**

*   **Python Dictionaries are _Convenient_ for secrets:** This library has evolved from my self-guided, educational development of some microservices to enrich my world.  
*   **Kubernetes Authentication Integration:**  The library utilizes Hashicorp Vault's Kubernetes authentication mechanism ensuring that only authorized entities can access and manipulate secrets. Since the Kubernetes Service Account token required for authentication is generated on-demand and has a TTL of 10 minutes (minimum allowed by Kubernetes), there is no stored token for vault authentication (no standing privileges). Furthermore, the retrieved Vault token's time-to-live is only 10 seconds - this ephemeral authentication dramatically reducing the exposure of the login token.  In testing, the vault login's TTL could be reduced to 1 second.
*   **Kubernetes Encrypted Secrets:**  The actual secrets (JSON file corresponding to the Python Dictionary) are only stored as the _Ciphertext_ resulting from 'Transit' AES-256 encryption of that file, so Key material never touches disk/memory in the cluster.
*   **AES-256 Transit Encryption/Decryption as a Service:**  I leverage HashiCorp Vault' Transit feature - providing AES-256 encryption and decryption _as a Service_. The encryption of the plaintext secrets and decryption of the ciphertext is handled by the vault which requires the use or x509 RFC 2818 certificates with IP-based SANs to ensure the communication is secure between the Kubernetes cluster and the external Vault. This provides strong, transport-level protection for your secrets during transit, significantly reducing the risk of interception.
*   **Automated Key Rotation:**  Given the actual frequency of accessing the secrets (a few times per week), the actual risk of compromise of the AES-256 key is low (but not zero) - key rotation can reduce the risk even lower.  The `recryptonator` implements this by periodically rotating the transit key, mitigating the risk associated with long-lived keys and bolstering security.
*   **Streamlined Workflow:** These three examples (Encryptionator, Kubevault-Example, and Recryptonator) guide you through the complete process, making it easier to implement a secure secret management strategy.

1.  **Encryptonator: Initial Secret Encryption**

    *   **What it Does:** The `Encryptionator` initially encrypts your secrets dictionary using the current transit key, and stores the ciphertext as a Kubernetes secret. The connection details for connecting the Kubernetes cluster and the Vault are provided in the config dictionary.  The remaining values (file_path to the plaintext JSON file, the name of the transit_key, the namespace, name, secret_data_name, and read_type of the destination Kubernetes secret) are also specified in the frontmatter of the code.  If validate is set to True, after the ciphertext is stored in the Kubernetes secret, it is retrieved, decrypted and compared to the source dictionary.  The example [priviledge file](https://github.com/dekeyrej/secretmanager/tree/main/examples/encryptonator/my-app-policy.hcl) provides a 'least priviledge' approach.
    *   **Use Case:** The initial step in securing your secrets for transport. Ideally only used once in your clusters lifecycle.
    *   **Usage:** `python encryptionator.py`
    *   **[Link to Encryptionator Code](https://github.com/dekeyrej/secretmanager/tree/main/tools/encryptonator)**

2.  **Kubevault-Example: Just What Your Application Needs**
    *   **What it Does:**  This example demonstrates the secure extraction and decryption of the encrypted secrets using the current transit key.  It's a critical step in verifying the system's functionality. This is the 'read stub' if you will for your application to retrieve it's secrets at initialization.  The same connection parameters are again enumerated in the config dictionary. In this instance though, there is a second 'secretdef' dictionary that captures all of the parameters for the particular secret to be retrieved/decrypted.
    *   **Use Case:** Validates the decryption process and how to access the decrypted secrets. Note, that in my usage the secretmanager is instantiated, the secrets read, the necessary values applied to the microservice and the entire secretmanager instance is deleted - no lingering environment variables, no files.  The only place the minimally necessary secrets for that microservice exist are in the ephemeral, running python code.
    *   **Usage:** `python kubevault_example.py`
    *   **[Link to Kubevault-Example Code](https://github.com/dekeyrej/secretmanager/tree/main/examples/kubevault-example.py)**

3.  **Recryptonator: Scheduled, Automated Key Rotation**
    *   **What it Does:** This component automatically rotates the transit key (a feature provided by the Vault), providing a core component of a robust secret management strategy that ensures key lifecycle hygiene.  This is where the magic happens – securing the key itself. Of course, simply rotating the key would break the entire mechanism - the new key will not work to decrypt the ciphertext created with the old key, so recryptonator grabs the ciphertext from the Kubetnetes secret, decrypts it into plaintext using the current key, rotates the key, reencrypts the plaintext into ciphertext using the new key, and stores the new ciphertext into the Kubernetes secret.  This rotation is scheduled as a CronJob at whatever frequency is necessary to minimize exposure of the transit key (I rotate mine once per month).  Like encryptonator.py, the connection and secret data are provided in the frontmatter of the example.
    *   **Use Case:**  Automated key rotation minimizes the impact of a compromised transit key.
    *   **Command:** `python recryptonator.py`
    *   **[Link to Recryptonator Code](https://github.com/dekeyrej/secretmanager/tree/main/tools/recryptonator)**

**Targeting Security Professionals**

I hope that this project will pique the interest of security professionals exploring more secure secret management strategies for their Kubernetes environments.  It’s designed to be a practical demonstration of key principles and techniques.
