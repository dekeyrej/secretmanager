# secretmanager/secretregistry.py

from secretmanager._kubevault_ops import (
    init_kubevault,
    read_encrypted_secrets,
    create_encrypted_secret,
    rotate_vault_key,
    logout_kubevault,
)

from secretmanager._k8s_ops import (
    connect_to_k8s,
    read_k8s_secret,
    create_k8s_secret,
    logout_k8s,
)

from secretmanager._source_loader import (
    read_secrets_from_file,
    read_secrets_from_env,
    create_secrets_file,
    init_file,
    init_environment,
    logout_file,
    logout_environment,
)

SECRET_VERB_REGISTRY = {
    "KUBEVAULT": {
        "INIT": init_kubevault,
        "READ": read_encrypted_secrets,
        "CREATE": create_encrypted_secret,
        "ROTATE": rotate_vault_key,
        "LOGOUT": logout_kubevault,
    },
    "KUBERNETES": {
        "INIT": connect_to_k8s,
        "READ": read_k8s_secret,
        "CREATE": create_k8s_secret,
        "LOGOUT": logout_k8s,
    },
    "FILE": {
        "INIT": init_file,
        "READ": read_secrets_from_file,
        "CREATE": create_secrets_file,
        "LOGOUT": logout_file,
    },
    "ENVIRONMENT": {
        "INIT": init_environment,
        "READ": read_secrets_from_env,
        "LOGOUT": logout_environment,
    },
}
