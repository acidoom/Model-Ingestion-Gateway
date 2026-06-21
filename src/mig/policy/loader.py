"""Load a :class:`~mig.policy.schema.Policy` from a JSON or YAML file.

JSON is parsed with the stdlib (zero deps). YAML requires the optional
``mig[policy]`` extra and is parsed with ``yaml.safe_load`` **only** — never the
arbitrary-object ``yaml.load`` — so loading a policy can never execute code.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping

from mig.policy.schema import Policy, PolicyError


def load_policy(path: str) -> Policy:
    """Load and validate a policy document (``.json`` / ``.yaml`` / ``.yml``)."""
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise PolicyError(f"could not read policy file {path!r}: {exc}") from exc

    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        data = _parse_json(text, path)
    elif ext in (".yaml", ".yml"):
        data = _parse_yaml(text, path)
    else:
        # Unknown extension: try JSON (a subset of YAML), then YAML.
        try:
            data = _parse_json(text, path)
        except PolicyError:
            data = _parse_yaml(text, path)

    if not isinstance(data, Mapping):
        raise PolicyError(f"policy {path!r} must be a mapping at the top level")
    return Policy.from_mapping(data)


def _parse_json(text: str, path: str) -> object:
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise PolicyError(f"invalid JSON policy {path!r}: {exc}") from exc


def _parse_yaml(text: str, path: str) -> object:
    try:
        import yaml
    except ImportError as exc:
        raise PolicyError(
            "YAML policies require the optional dependency; install it with: "
            "pip install 'mig[policy]'"
        ) from exc
    try:
        return yaml.safe_load(text)
    except Exception as exc:  # yaml.YAMLError (untyped module) → normalise
        raise PolicyError(f"invalid YAML policy {path!r}: {exc}") from exc
