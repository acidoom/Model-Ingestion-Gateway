"""I2: safetensors headers parse without deserializing tensors, hardened against
adversarial input (oversized/overflowing/truncated declared lengths, bad JSON).
"""

from __future__ import annotations

import pathlib
import struct

import pytest

from conftest import write_safetensors
from mig.gates._safetensors import (
    MAX_HEADER_BYTES,
    SafetensorsError,
    read_safetensors_header,
    tensor_names,
)


def _write(path: pathlib.Path, declared: int, body: bytes, *, tail: bytes = b"") -> None:
    path.write_bytes(struct.pack("<Q", declared) + body + tail)


def test_reads_a_valid_header(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "m.safetensors"
    write_safetensors(path)
    header = read_safetensors_header(str(path))
    assert "weight" in header
    assert tensor_names(header) == ["weight"]


def test_metadata_key_excluded_from_tensor_names(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "m.safetensors"
    write_safetensors(path, metadata={"format": "pt"})
    header = read_safetensors_header(str(path))
    assert tensor_names(header) == ["weight"]


def test_rejects_file_smaller_than_prefix(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "x"
    path.write_bytes(b"\x00\x00")
    with pytest.raises(SafetensorsError):
        read_safetensors_header(str(path))


def test_rejects_zero_length_header(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "x"
    _write(path, 0, b"")
    with pytest.raises(SafetensorsError):
        read_safetensors_header(str(path))


def test_rejects_oversized_declared_length(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "x"
    _write(path, MAX_HEADER_BYTES + 1, b"{}")
    with pytest.raises(SafetensorsError):
        read_safetensors_header(str(path))


def test_rejects_declared_length_past_eof(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "x"
    _write(path, 4096, b"{}")  # declares 4096 but only 2 bytes follow
    with pytest.raises(SafetensorsError):
        read_safetensors_header(str(path))


def test_rejects_invalid_json_header(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "x"
    body = b"not json at all"
    _write(path, len(body), body)
    with pytest.raises(SafetensorsError):
        read_safetensors_header(str(path))


def test_rejects_non_object_header(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "x"
    body = b"[1, 2, 3]"
    _write(path, len(body), body)
    with pytest.raises(SafetensorsError):
        read_safetensors_header(str(path))


def test_does_not_require_tensor_bytes_to_be_present(tmp_path: pathlib.Path) -> None:
    # The header is fully parseable even though the declared tensor region
    # (data_offsets up to 4) is absent — proof we never read tensor bytes.
    path = tmp_path / "x"
    body = b'{"weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}'
    _write(path, len(body), body)  # no 4 tensor bytes appended
    header = read_safetensors_header(str(path))
    assert tensor_names(header) == ["weight"]
