"""IssuerRegistryClient — async Python client for the IssuerRegistry contract."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from eth_typing import ChecksumAddress
from pydantic import BaseModel
from web3 import AsyncWeb3
from web3.types import TxReceipt

from common.chain.base import ContractClient


class IssuerRecordModel(BaseModel):
    """Typed representation of an on-chain IssuerRecord struct."""

    did: str
    did_hash: str  # hex-encoded keccak256
    name: str
    description: str
    registered_at: datetime
    updated_at: datetime
    active: bool
    metadata_uri: str


class IssuerRegistryClient(ContractClient):
    """Async client for the ``IssuerRegistry`` transparent proxy."""

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

    async def is_issuer_active(self, did: str) -> bool:
        """Return ``True`` if *did* is currently active in the registry."""
        return await self.async_call("isIssuerActive", did)

    async def get_issuer(self, did: str) -> Optional[IssuerRecordModel]:
        """Fetch the full :class:`IssuerRecordModel` for *did*, or ``None`` if not found."""
        try:
            raw = await self.async_call("getIssuer", did)
        except Exception:
            return None

        return IssuerRecordModel(
            did=raw[0],
            did_hash=raw[0],  # hash computed off-chain for display
            name=raw[1],
            description=raw[2],
            registered_at=datetime.fromtimestamp(int(raw[3]), tz=timezone.utc),
            updated_at=datetime.fromtimestamp(int(raw[4]), tz=timezone.utc),
            active=bool(raw[5]),
            metadata_uri=raw[6],
        )

    async def get_issuer_count(self) -> int:
        """Return the number of currently active issuers."""
        return int(await self.async_call("getIssuerCount"))

    # ------------------------------------------------------------------
    # State-changing methods
    # ------------------------------------------------------------------

    async def register_issuer(
        self,
        did: str,
        name: str,
        description: str,
        metadata_uri: str,
        *,
        private_key: str,
    ) -> TxReceipt:
        """Register a new trusted issuer DID.

        Args:
            did:          W3C DID string (e.g. ``"did:key:z6Mk..."``).
            name:         Human-readable name.
            description:  Short description.
            metadata_uri: Optional IPFS or HTTPS URI for extended metadata.
            private_key:  Signing key for the ISSUER_ADMIN_ROLE holder.

        Returns:
            Mined transaction receipt.
        """
        return await self.async_transact(
            "registerIssuer", did, name, description, metadata_uri,
            private_key=private_key,
        )

    async def revoke_issuer(self, did: str, *, private_key: str) -> TxReceipt:
        """Revoke an active issuer DID."""
        return await self.async_transact("revokeIssuer", did, private_key=private_key)

    async def update_issuer(
        self,
        did: str,
        name: str,
        description: str,
        metadata_uri: str,
        *,
        private_key: str,
    ) -> TxReceipt:
        """Update mutable fields (name, description, metadataURI) for an issuer."""
        return await self.async_transact(
            "updateIssuer", did, name, description, metadata_uri,
            private_key=private_key,
        )
