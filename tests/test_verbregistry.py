import pytest

from secretmanager.verbregistry import VerbRegistry


def test_get_handler_unknown_source():
    registry = VerbRegistry({})
    with pytest.raises(ValueError, match="Unknown source:"):
        registry.get_handler("ghost", "INIT")


def test_get_handler_unknown_verb():
    registry = VerbRegistry({"FILE": {"INIT": lambda: "ok"}})
    with pytest.raises(ValueError, match="Unknown verb 'FLUSH' for source 'FILE'"):
        registry.get_handler("FILE", "FLUSH")


def test_safe_get_handler_returns_none():
    registry = VerbRegistry({})
    handler = registry.safe_get_handler("ghost", "INIT")
    assert handler is None


def test_list_sources():
    registry = VerbRegistry({"FILE": {}, "ENV": {}})
    assert set(registry.list_sources()) == {"FILE", "ENV"}


def test_list_verbs():
    registry = VerbRegistry({"FILE": {"INIT": lambda: None, "CREATE": lambda: None}})
    verbs = registry.list_verbs("file")
    assert set(verbs) == {"INIT", "CREATE"}


def test_validate_raises_on_non_callable():
    registry = VerbRegistry({"FILE": {"INIT": "not-a-function"}})
    with pytest.raises(TypeError, match="Handler for FILE:INIT is not callable"):
        registry.validate()


def test_validate_passes_on_valid_registry():
    registry = VerbRegistry({"FILE": {"INIT": lambda: None}})
    registry.validate()  # Should not raise
