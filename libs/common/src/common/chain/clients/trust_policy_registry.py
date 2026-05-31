"""TrustPolicyRegistryClient — async Python client for TrustPolicyRegistry."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from eth_typing import ChecksumAddress
from pydantic import BaseModel
from web3 import AsyncWeb3
from web3.types import TxReceipt

from common.chain.base import ContractClient


class TrustPolicyModel(BaseModel):
    """Typed representation of an on-chain TrustPolicy struct."""

    service_id: str
    allowed_issuer_dids: list[str]
    required_credential_types: list[str]
    version: int
    created_at: datetime
    updated_at: datetime
    active: bool
    description: str


class TrustPolicyRegistryClient(ContractClient):
    """Async client for the ``TrustPolicyRegistry`` transparent proxy."""

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

    async def is_policy_active(self, service_id: str) -> bool:
        """Return ``True`` if a policy exists and is active for *service_id*."""
        return await self.async_call("isPolicyActive", service_id)

    async def get_policy(self, service_id: str) -> Optional[TrustPolicyModel]:
        """Fetch the current active policy for *service_id*, or ``None``."""
        try:
            raw = await self.async_call("getPolicy", service_id)
        except Exception:
            return None
        return _raw_to_policy(raw)

    async def get_policy_history(self, service_id: str) -> list[TrustPolicyModel]:
        """Return all previous versions of a policy (oldest first)."""
        raw_list = await self.async_call("getPolicyHistory", service_id)
        return [_raw_to_policy(r) for r in raw_list]

    async def get_policy_count(self) -> int:
        """Return the number of active policies."""
        return int(await self.async_call("getPolicyCount"))

    async def is_issuer_allowed_for_service(self, service_id: str, issuer_did: str) -> bool:
        """Return ``True`` if *issuer_did* is in the allowlist for *service_id*."""
        return await self.async_call("isIssuerAllowedForService", service_id, issuer_did)

    # ------------------------------------------------------------------
    # State-changing methods
    # ------------------------------------------------------------------

    async def create_policy(
        self,
        service_id: str,
        allowed_issuer_dids: list[str],
        required_credential_types: list[str],
        description: str,
        *,
        private_key: str,
    ) -> TxReceipt:
        """Create a new trust policy for *service_id*."""
        return await self.async_transact(
            "createPolicy",
            service_id,
            allowed_issuer_dids,
            required_credential_types,
            description,
            private_key=private_key,
        )

    async def update_policy(
        self,
        service_id: str,
        allowed_issuer_dids: list[str],
        required_credential_types: list[str],
        description: str,
        *,
        private_key: str,
    ) -> TxReceipt:
        """Update an existing policy (archives the current version to history)."""
        return await self.async_transact(
            "updatePolicy",
            service_id,
            allowed_issuer_dids,
            required_credential_types,
            description,
            private_key=private_key,
        )

    async def deactivate_policy(self, service_id: str, *, private_key: str) -> TxReceipt:
        """Deactivate a policy, removing it from the active index."""
        return await self.async_transact("deactivatePolicy", service_id, private_key=private_key)


def _raw_to_policy(raw: tuple) -> TrustPolicyModel:
    return TrustPolicyModel(
        service_id=raw[0],
        allowed_issuer_dids=list(raw[1]),
        required_credential_types=list(raw[2]),
        version=int(raw[3]),
        created_at=datetime.fromtimestamp(int(raw[4]), tz=timezone.utc),
        updated_at=datetime.fromtimestamp(int(raw[5]), tz=timezone.utc),
        active=bool(raw[6]),
        description=raw[7],
    )
