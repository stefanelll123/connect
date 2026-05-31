"""ABI loader — resolves contract ABIs from the compiled contracts/abis/ directory."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# Module-level ABI cache: contract_name → ABI list
_ABI_CACHE: dict[str, list[Any]] = {}

# Guard against directory traversal in contract names
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def load_abi(contract_name: str, contracts_root: Path = Path("contracts")) -> list[Any]:
    """Load and cache the ABI for *contract_name* from the abis/ directory.

    Args:
        contract_name: Name of the contract (e.g. ``"IssuerRegistry"``).
                       Must contain only alphanumeric characters, underscores,
                       or hyphens — no path separators or ``..`` segments.
        contracts_root: Filesystem path to the ``contracts/`` project root.
                        Defaults to the working-directory-relative ``contracts/``.

    Returns:
        Parsed ABI as a list of dicts.

    Raises:
        ValueError: If *contract_name* contains unsafe characters (traversal guard).
        FileNotFoundError: If the ABI file does not exist (run ``make export-abis``).
    """
    if not _SAFE_NAME_RE.match(contract_name):
        raise ValueError(
            f"Unsafe contract name: {contract_name!r}. "
            "Only alphanumeric, underscore, and hyphen characters are allowed."
        )

    if contract_name in _ABI_CACHE:
        return _ABI_CACHE[contract_name]

    abi_path = contracts_root / "abis" / f"{contract_name}.abi.json"
    if not abi_path.exists():
        raise FileNotFoundError(
            f"ABI file not found: {abi_path}. "
            "Run 'cd contracts && npm run export-abis' to generate ABI files."
        )

    with abi_path.open(encoding="utf-8") as fh:
        abi = json.load(fh)

    _ABI_CACHE[contract_name] = abi
    return abi


def clear_cache() -> None:
    """Flush the in-memory ABI cache (useful in tests)."""
    _ABI_CACHE.clear()
