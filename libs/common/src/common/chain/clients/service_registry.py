"""ServiceRegistryClient — async Python client for ServiceRegistry."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from eth_typing import ChecksumAddress
from pydantic import BaseModel
from web3 import AsyncWeb3
from web3.types import TxReceipt

from common.chain.base import ContractClient


class ServiceRecordModel(BaseModel):
    """Typed representation of an on-chain ServiceRecord struct."""

    service_id: str
    did: str
    base_url: str
    role: str
    active: bool
    registered_at: datetime
    updated_at: datetime
    description: str


class ServiceRegistryClient(ContractClient):
    """Async client for the ``ServiceRegistry`` transparent proxy."""

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

    async def is_service_active(self, service_id: str) -> bool:
        """Return ``True`` if *service_id* is currently active."""
        return await self.async_call("isServiceActive", service_id)

    async def get_service(self, service_id: str) -> Optional[ServiceRecordModel]:
        """Fetch the full :class:`ServiceRecordModel` for *service_id*, or ``None``."""
        try:
            raw = await self.async_call("getService", service_id)
        except Exception:
            return None
        return _raw_to_service(raw)

    async def get_services_by_role(self, role: str) -> list[ServiceRecordModel]:
        """Return all active services with the given *role* (``"producer"`` or ``"consumer"``)."""
        raw_list = await self.async_call("getServicesByRole", role)
        return [_raw_to_service(r) for r in raw_list]

    async def get_service_count(self) -> int:
        """Return the total number of active registered services."""
        return int(await self.async_call("getServiceCount"))

    # ------------------------------------------------------------------
    # State-changing methods
    # ------------------------------------------------------------------

    async def register_service(
        self,
        service_id: str,
        did: str,
        base_url: str,
        role: str,
        description: str,
        *,
        private_key: str,
    ) -> TxReceipt:
        """Register a new service endpoint."""
        return await self.async_transact(
            "registerService", service_id, did, base_url, role, description,
            private_key=private_key,
        )

    async def update_service(
        self,
        service_id: str,
        new_base_url: str,
        description: str,
        *,
        private_key: str,
    ) -> TxReceipt:
        """Update the base URL and description for an existing service."""
        return await self.async_transact(
            "updateService", service_id, new_base_url, description,
            private_key=private_key,
        )

    async def deregister_service(self, service_id: str, *, private_key: str) -> TxReceipt:
        """Deregister a service, removing it from all indexes."""
        return await self.async_transact(
            "deregisterService", service_id, private_key=private_key
        )


def _raw_to_service(raw: tuple) -> ServiceRecordModel:
    return ServiceRecordModel(
        service_id=raw[0],
        did=raw[1],
        base_url=raw[2],
        role=raw[3],
        active=bool(raw[4]),
        registered_at=datetime.fromtimestamp(int(raw[5]), tz=timezone.utc),
        updated_at=datetime.fromtimestamp(int(raw[6]), tz=timezone.utc),
        description=raw[7],
    )
