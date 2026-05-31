"""Chain settings — Pydantic BaseSettings for blockchain connectivity."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import SecretStr
from pydantic_settings import BaseSettings


class ChainSettings(BaseSettings):
    """Configuration loaded from environment variables for blockchain access."""

    rpc_url: str = "http://localhost:8545"
    """WebSocket (ws://) or HTTP (http://) RPC endpoint."""

    deployer_private_key: Optional[SecretStr] = None
    """EOA private key for signing transactions. Never log the revealed value."""

    network_chain_id: int = 31337
    """Expected chain ID — used for URL validation and delay configuration."""

    contracts_path: Path = Path("contracts")
    """Filesystem root of the compiled contracts/ directory (for ABI loading)."""

    model_config = {
        "env_prefix": "BLOCKCHAIN_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }
