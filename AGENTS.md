# AGENTS.md

## Developer Commands
- **Tests**: `pytest`
- **Version Bump**: `bumpver update --allow-dirty --patch`
- **Build**: `python -m build`
- **Check Distribution**: `twine check dist/*`

## Architecture Notes
- **Purpose**: Zero Trust ephemeral authentication for K8s secrets using HashiCorp Vault Transit (AES-256).
- **Core Components**:
  - `secretmanager/manager.py`: Main orchestrator.
  - `secretmanager/_vault_ops.py`: Vault interaction logic.
  - `secretmanager/_k8s_ops.py`: Kubernetes secret management.
- **Security Model**: Secrets are stored as Vault-encrypted ciphertext in K8s; decryption happens in memory using short-lived Vault tokens.

## Constraints & Quirks
- **Python Version**: Compatible with Python $\le$ 3.12. May fail on 3.13+ (see `docs/python_ssl_summary.md`).
- **Dependencies**: Relies on `hvac` for Vault and `kubernetes` for K8s API.
