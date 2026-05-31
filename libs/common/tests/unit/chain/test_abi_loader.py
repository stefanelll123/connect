"""Unit tests for common.chain.abi_loader."""

import json
import re
import pytest
from pathlib import Path

from common.chain.abi_loader import load_abi, clear_cache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_abi(tmp_path: Path, name: str, data: list) -> Path:
    abi_dir = tmp_path / "abis"
    abi_dir.mkdir(parents=True, exist_ok=True)
    abi_file = abi_dir / f"{name}.abi.json"
    abi_file.write_text(json.dumps(data))
    return tmp_path


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------

class TestLoadAbi:
    def test_loads_valid_abi(self, tmp_path: Path):
        expected = [{"type": "function", "name": "foo"}]
        root = _write_abi(tmp_path, "MyContract", expected)
        result = load_abi("MyContract", root)
        assert result == expected

    def test_abi_caching(self, tmp_path: Path):
        clear_cache()
        data = [{"type": "fallback"}]
        root = _write_abi(tmp_path, "Cached", data)
        first = load_abi("Cached", root)
        second = load_abi("Cached", root)
        assert first is second  # same object from cache

    def test_clear_cache_forces_reload(self, tmp_path: Path):
        clear_cache()
        data = [{"type": "receive"}]
        root = _write_abi(tmp_path, "ToReset", data)
        first = load_abi("ToReset", root)
        clear_cache()
        second = load_abi("ToReset", root)
        assert first == second
        assert first is not second  # different object — re-read from disk


# ---------------------------------------------------------------------------
# Security tests — path traversal guard
# ---------------------------------------------------------------------------

class TestPathTraversalGuard:
    @pytest.mark.parametrize("bad_name", [
        "../etc/passwd",
        "../../secret",
        "foo/bar",
        "foo\\bar",
        "foo;bar",
        "foo bar",
        "",
    ])
    def test_rejects_dangerous_names(self, tmp_path: Path, bad_name: str):
        with pytest.raises((ValueError, FileNotFoundError)):
            load_abi(bad_name, tmp_path)


# ---------------------------------------------------------------------------
# Error tests
# ---------------------------------------------------------------------------

class TestAbiErrors:
    def test_missing_abi_raises_file_not_found(self, tmp_path: Path):
        (tmp_path / "abis").mkdir()
        with pytest.raises(FileNotFoundError):
            load_abi("NonExistent", tmp_path)

    def test_invalid_json_raises(self, tmp_path: Path):
        abi_dir = tmp_path / "abis"
        abi_dir.mkdir()
        (abi_dir / "Bad.abi.json").write_text("NOT JSON{{{{")
        with pytest.raises(Exception):
            load_abi("Bad", tmp_path)
