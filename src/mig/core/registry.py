"""Plugin registry — discover sources / gates / sandboxes / stores.

Adapters register either in-process (``register``) or via packaging
entry-points (``importlib.metadata``), so an installed extra like
``mig[huggingface]`` can contribute a source without MIG importing it eagerly.

The registry stores **factories** (zero-arg callables), not instances, so
discovery never constructs — let alone *runs* — an adapter as a side effect of
import. That keeps the supply-chain posture honest (I10): listing what is
installed must not execute it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from importlib import metadata
from typing import Generic, TypeVar

T = TypeVar("T")

#: Entry-point groups MIG looks up.
GATE_GROUP = "mig.gates"
SOURCE_GROUP = "mig.sources"
SANDBOX_GROUP = "mig.sandboxes"
STORE_GROUP = "mig.stores"


@dataclass
class Registry(Generic[T]):
    """A named collection of zero-arg factories for one plugin kind."""

    group: str
    _factories: dict[str, Callable[[], T]] = field(default_factory=dict)

    def register(self, name: str, factory: Callable[[], T]) -> None:
        """Register ``factory`` under ``name`` (overwrites an existing name)."""
        self._factories[name] = factory

    def discover(self) -> None:
        """Load entry-points for this registry's group.

        Each entry-point's *value* is loaded (the class/callable it points to)
        and stored as a factory. Loading an entry-point imports its module —
        which is unavoidable for plugin discovery — but the registry never
        *calls* the loaded object here.
        """
        for entry_point in metadata.entry_points(group=self.group):
            self._factories[entry_point.name] = entry_point.load

    def create(self, name: str) -> T:
        """Instantiate the plugin registered under ``name``."""
        try:
            factory = self._factories[name]
        except KeyError:
            raise KeyError(
                f"no plugin {name!r} registered in group {self.group!r}; "
                f"known: {sorted(self._factories)}"
            ) from None
        return factory()

    def names(self) -> list[str]:
        """Sorted list of registered names."""
        return sorted(self._factories)

    def __contains__(self, name: object) -> bool:
        return name in self._factories

    def __iter__(self) -> Iterator[str]:
        return iter(self.names())


def gate_registry() -> Registry[object]:
    """A fresh gate registry (call :meth:`Registry.discover` to populate)."""
    return Registry(group=GATE_GROUP)


def source_registry() -> Registry[object]:
    """A fresh source registry."""
    return Registry(group=SOURCE_GROUP)


def sandbox_registry() -> Registry[object]:
    """A fresh sandbox registry."""
    return Registry(group=SANDBOX_GROUP)


def store_registry() -> Registry[object]:
    """A fresh trusted-store registry."""
    return Registry(group=STORE_GROUP)
