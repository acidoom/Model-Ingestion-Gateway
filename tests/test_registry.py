"""Plugin registry: register / create / discover, without executing plugins."""

from __future__ import annotations

import pytest

from mig.core.registry import (
    GATE_GROUP,
    Registry,
    gate_registry,
    sandbox_registry,
    source_registry,
    store_registry,
)


class _Marker:
    created = False

    def __init__(self) -> None:
        _Marker.created = True


def test_register_and_create() -> None:
    reg: Registry[_Marker] = Registry(group="test")
    reg.register("marker", _Marker)
    assert "marker" in reg
    assert reg.names() == ["marker"]
    instance = reg.create("marker")
    assert isinstance(instance, _Marker)


def test_registering_does_not_construct() -> None:
    _Marker.created = False
    reg: Registry[_Marker] = Registry(group="test")
    reg.register("marker", _Marker)
    # Discovery/registration must not instantiate (let alone run) a plugin.
    assert _Marker.created is False
    reg.create("marker")
    assert _Marker.created is True


def test_create_unknown_raises_keyerror() -> None:
    reg: Registry[_Marker] = Registry(group="test")
    with pytest.raises(KeyError):
        reg.create("nope")


def test_factory_helpers_have_expected_groups() -> None:
    assert gate_registry().group == GATE_GROUP
    assert source_registry().group == "mig.sources"
    assert sandbox_registry().group == "mig.sandboxes"
    assert store_registry().group == "mig.stores"


def test_discover_with_no_entrypoints_is_empty() -> None:
    # No mig.gates entry-points are installed in the test env.
    reg = gate_registry()
    reg.discover()
    assert reg.names() == []
