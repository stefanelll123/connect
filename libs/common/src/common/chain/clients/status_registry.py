"""StatusRegistryClient — async Python client for StatusRegistry."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from eth_typing import ChecksumAddress
from pydantic import BaseModel
from web3 import AsyncWeb3
from web3.types import TxReceipt

from common.chain.base import ContractClient


class StatusAnchorModel(BaseModel):
    """Typed representation of an on-chain StatusAnchor struct."""

    issuer_did_hash: str        # bytes32 hex
    status_list_index: int
    credential_hash: str        # bytes32 hex
    status_list_url: str
    published_at: datetime
    freshness_delta_seconds: int
    active: bool


class StatusRegistryClient(ContractClient):
    """Async client for the ``StatusRegistry`` transparent proxy."""

    def __init__(
        self,
        web3: AsyncWeb3,
        address: ChecksumAddress,
        abi: list,
    ) -> None:
        super().__init__(web3, address, abi)

    # ------------------------------------------------------------------
    # Read-only methods
    # ------------------------------------------------------------------

    async def get_status_anchor(
        self,
        issuer_did: str,
        status_list_index: int,
    ) -> Optional[StatusAnchorModel]:
        """Fetch the anchor for *(issuer_did, status_list_index)*, or ``None``."""
        try:
            raw = await self.async_call("getStatusAnchor", issuer_did, status_list_index)
        except Exception:
            return None
        return _raw_to_anchor(raw)

    async def verify_status_anchor(
        self,
        issuer_did: str,
        status_list_index: int,
        credential_hash: bytes,
    ) -> bool:
        """Return ``True`` if *credential_hash* matches the stored anchor."""
        return await self.async_call(
            "verifyStatusAnchor", issuer_did, status_list_index, credential_hash
        )

    async def get_freshness_delta(self, issuer_did: str, status_list_index: int) -> int:
        """Return the freshness delta in seconds for an anchor."""
        return int(await self.async_call("getFreshnessDelta", issuer_did, status_list_index))

    # ------------------------------------------------------------------
    # State-changing methods
    # ------------------------------------------------------------------

    async def publish_status_anchor(
        self,
        issuer_did: str,
        status_list_index: int,
        credential_hash: bytes,
        status_list_url: str,
        freshness_delta_seconds: int,
        *,
        private_key: str,
    ) -> TxReceipt:
        """Publish or update a Bitstring Status List anchor."""
        return await self.async_transact(
            "publishStatusAnchor",
            issuer_did,
            status_list_index,
            credential_hash,
            status_list_url,
            freshness_delta_seconds,
            private_key=private_key,
        )

    async def emit_emergency_revocation(
        self,
        credential_hash: bytes,
        reason: str,
        *,
        private_key: str,
    ) -> TxReceipt:
        """Emit an emergency revocation event (no on-chain state change)."""
        return await self.async_transact(
            "emitEmergencyRevocation", credential_hash, reason, private_key=private_key
        )


def _raw_to_anchor(raw: tuple) -> StatusAnchorModel:
    return StatusAnchorModel(
        issuer_did_hash=raw[0].hex() if isinstance(raw[0], bytes) else str(raw[0]),
        status_list_index=int(raw[1]),
        credential_hash=raw[2].hex() if isinstance(raw[2], bytes) else str(raw[2]),
        status_list_url=raw[3],
        published_at=datetime.fromtimestamp(int(raw[4]), tz=timezone.utc),
        freshness_delta_seconds=int(raw[5]),
        active=bool(raw[6]),
    )
