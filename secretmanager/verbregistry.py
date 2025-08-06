# secretmanager/verbregistry.py
# REGISTRY = {}

# def register(source, verb):
#     def decorator(func):
#         REGISTRY.setdefault(source.upper(), {})[verb.upper()] = func
#         return func
#     return decorator


class VerbRegistry:
    VERBS = {"INIT", "READ", "CREATE", "ROTATE", "LOGOUT"}

    def __init__(self, registry):
        self._registry = registry  # or REGISTRY

    def get_handler(self, source: str, verb: str):
        source_map = self._registry.get(source.upper())
        if not source_map:
            raise ValueError(f"Unknown source: {source}")
        handler = source_map.get(verb.upper())
        if not handler:
            raise ValueError(f"Unknown verb '{verb}' for source '{source}'")
        return handler

    def list_sources(self):
        return list(self._registry.keys())

    def list_verbs(self, source: str):
        return list(self._registry.get(source.upper(), {}).keys())

    def validate(self):
        for source, verbs in self._registry.items():
            for verb, handler in verbs.items():
                if not callable(handler):
                    raise TypeError(f"Handler for {source}:{verb} is not callable")

    def perform(self, backend: str, verb: str, *args, **kwargs):
        handler = self.get_handler(backend, verb)
        return handler(*args, **kwargs)

    def safe_get_handler(self, backend: str, verb: str):
        try:
            return self.get_handler(backend, verb)
        except ValueError:
            return None
