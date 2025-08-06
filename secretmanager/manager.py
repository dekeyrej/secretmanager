import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecretManager:
    """A class to manage secrets from various sources: file,
    environment variables, Kubernetes, and Vault."""

    SOURCES = {"FILE", "ENVIRONMENT", "KUBERNETES", "KUBEVAULT"}

    def __init__(self, config: dict = None, log_level=logging.INFO):
        logging.basicConfig(
            level=log_level, format="%(asctime)s - %(levelname)s - %(message)s"
        )
        from secretmanager.verbregistry import VerbRegistry
        from secretmanager.secretregistry import SECRET_VERB_REGISTRY

        self.registry = VerbRegistry(SECRET_VERB_REGISTRY)
        self.k8s_client = None
        self.hvac_client = None
        self.config = None
        if not config:
            logger.info(
                "No configuration provided. Call configure_secret_type with a valid secret_type."
            )
        else:
            self.configure_secret_type(config)

    def configure_secret_type(self, config: dict):
        if config.get("SOURCE") not in self.SOURCES:
            raise ValueError(
                f"Invalid configuration source. Must be one of: {', '.join(self.SOURCES)}."
            )
        if not self.config:
            logger.info(
                f"SecretManager initializing with source: {config.get('SOURCE')}"
            )
        elif self.config and self.config.get("SOURCE") != config.get("SOURCE"):
            logger.info(
                f"""Changing configuration source from {self.config.get('SOURCE')} """
                f"""to {config.get('SOURCE')}"""
            )
            self.execute(self.config.get("SOURCE"), "LOGOUT")
        elif self.config and self.config.get("SOURCE") == config.get("SOURCE"):
            logger.info(
                f"SecretManager already configured with source: {self.config.get('SOURCE')}"
            )
            return

        self.config = config
        self.execute(self.config.get("SOURCE"), "INIT", self)
        logger.info(f"SecretManager initialized with source: {config.get('SOURCE')}")

    def execute(self, backend: str, verb: str, *args, **kwargs):
        return self.registry.perform(backend, verb, *args, **kwargs)
