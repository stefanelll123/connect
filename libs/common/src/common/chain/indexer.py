"""ChainEventIndexer — polls contract events and updates local DB cache tables.

The indexer runs a continuous poll loop (default 15s) fetching emitted events
from all four registry contracts since the last indexed block, then persists
the results to the application database.

DB schema expected (PostgreSQL / SQLAlchemy):
  - issuers_cache         (did PK, did_hash, name, description, active, registered_at, synced_at)
  - trust_policies_cache  (service_id PK, allowed_issuer_dids JSONB, ...)
  - status_anchors_cache  (id PK, issuer_did, status_list_index, ...)
  - services_cache        (service_id PK, did, base_url, role, active, ...)
  - chain_sync_state      (contract_name UNIQUE, last_indexed_block, last_sync_at)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Coroutine, Optional

from web3 import AsyncWeb3

logger = logging.getLogger(__name__)

# Type alias for an async DB upsert callable
UpsertFn = Callable[[str, dict[str, Any]], Coroutine[Any, Any, None]]


class ChainEventIndexer:
    """Polls block-range event logs from the four registry contracts."""

    def __init__(
        self,
        web3: AsyncWeb3,
        contracts: dict[str, Any],  # name → web3 contract instance
        poll_interval: int = 15,
        upsert_fn: Optional[UpsertFn] = None,
        get_last_block_fn: Optional[Callable[[str], Coroutine[Any, Any, int]]] = None,
        save_last_block_fn: Optional[Callable[[str, int], Coroutine[Any, Any, None]]] = None,
    ) -> None:
        """
        Args:
            web3:               Connected :class:`AsyncWeb3` instance.
            contracts:          Mapping of ``contract_name → web3 contract object``.
            poll_interval:      Seconds between polling cycles (default 15).
            upsert_fn:          ``async (table, record_dict) -> None`` — saves a record to DB.
            get_last_block_fn:  ``async (contract_name) -> int`` — reads last indexed block from DB.
            save_last_block_fn: ``async (contract_name, block) -> None`` — persists last indexed block.
        """
        self._web3 = web3
        self._contracts = contracts
        self._poll_interval = poll_interval
        self._upsert = upsert_fn or self._noop_upsert
        self._get_last_block = get_last_block_fn or self._noop_get_block
        self._save_last_block = save_last_block_fn or self._noop_save_block
        self._running = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start the continuous polling loop. Runs until :meth:`stop` is called."""
        self._running = True
        logger.info("ChainEventIndexer started (poll_interval=%ds)", self._poll_interval)
        while self._running:
            try:
                await self._poll_all()
            except Exception as exc:
                logger.exception("Error during indexer poll cycle: %s", exc)
            await asyncio.sleep(self._poll_interval)

    def stop(self) -> None:
        """Signal the indexer to stop after the current poll cycle."""
        self._running = False

    # ------------------------------------------------------------------
    # Internal polling logic
    # ------------------------------------------------------------------

    async def _poll_all(self) -> None:
        latest_block = await self._web3.eth.get_block_number()

        for name, contract in self._contracts.items():
            try:
                from_block = (await self._get_last_block(name)) + 1
                if from_block > latest_block:
                    continue
                await self._process_contract(name, contract, from_block, latest_block)
                await self._save_last_block(name, latest_block)
            except Exception as exc:
                logger.exception("Error indexing contract %s: %s", name, exc)

    async def _process_contract(
        self,
        name: str,
        contract: Any,
        from_block: int,
        to_block: int,
    ) -> None:
        handlers: dict[str, Callable[[Any], Coroutine[Any, Any, None]]] = {
            "IssuerRegistry": self._handle_issuer_events,
            "TrustPolicyRegistry": self._handle_policy_events,
            "StatusRegistry": self._handle_status_events,
            "ServiceRegistry": self._handle_service_events,
        }
        handler = handlers.get(name)
        if handler is None:
            logger.warning("No event handler for contract: %s", name)
            return
        await handler(contract)

        # Fetch all events in the block range using eth_getLogs approach
        all_events = await contract.events.allEvents().get_logs(  # type: ignore[attr-defined]
            fromBlock=from_block,
            toBlock=to_block,
        ) if hasattr(contract.events, "allEvents") else []

        for event in all_events:
            await handler(event)

    # ------------------------------------------------------------------
    # Per-contract event handlers
    # ------------------------------------------------------------------

    async def _handle_issuer_events(self, event: Any) -> None:
        event_name = event.get("event", "")
        args = event.get("args", {})

        if event_name == "IssuerRegistered":
            await self._upsert("issuers_cache", {
                "did": args.get("did"),
                "did_hash": args.get("didHash", b"").hex(),
                "name": args.get("name"),
                "description": "",
                "active": True,
                "registered_at": None,  # resolved from block timestamp downstream
                "synced_at": "now()",
            })
        elif event_name == "IssuerRevoked":
            await self._upsert("issuers_cache", {
                "did": args.get("did"),
                "did_hash": args.get("didHash", b"").hex(),
                "active": False,
                "synced_at": "now()",
            })

    async def _handle_policy_events(self, event: Any) -> None:
        event_name = event.get("event", "")
        args = event.get("args", {})

        if event_name in ("PolicyCreated", "PolicyUpdated"):
            await self._upsert("trust_policies_cache", {
                "service_id": args.get("serviceId"),
                "version": args.get("version"),
                "active": True,
                "synced_at": "now()",
            })
        elif event_name == "PolicyDeactivated":
            await self._upsert("trust_policies_cache", {
                "service_id": args.get("serviceId"),
                "active": False,
                "synced_at": "now()",
            })

    async def _handle_status_events(self, event: Any) -> None:
        event_name = event.get("event", "")
        args = event.get("args", {})

        if event_name == "StatusAnchorPublished":
            issuer_hash = args.get("issuerDidHash", b"")
            cred_hash = args.get("credentialHash", b"")
            await self._upsert("status_anchors_cache", {
                "id": f"{issuer_hash.hex() if isinstance(issuer_hash, bytes) else issuer_hash}"
                      f"-{args.get('statusListIndex')}",
                "issuer_did_hash": issuer_hash.hex() if isinstance(issuer_hash, bytes) else str(issuer_hash),
                "status_list_index": args.get("statusListIndex"),
                "credential_hash": cred_hash.hex() if isinstance(cred_hash, bytes) else str(cred_hash),
                "status_list_url": args.get("statusListUrl"),
                "freshness_delta_seconds": args.get("freshnessDeltaSeconds"),
                "synced_at": "now()",
            })

    async def _handle_service_events(self, event: Any) -> None:
        event_name = event.get("event", "")
        args = event.get("args", {})

        if event_name == "ServiceRegistered":
            await self._upsert("services_cache", {
                "service_id": args.get("serviceId"),
                "did": args.get("did"),
                "base_url": args.get("baseUrl"),
                "role": args.get("role"),
                "active": True,
                "synced_at": "now()",
            })
        elif event_name == "ServiceDeregistered":
            await self._upsert("services_cache", {
                "service_id": args.get("serviceId"),
                "active": False,
                "synced_at": "now()",
            })
        elif event_name == "ServiceUpdated":
            await self._upsert("services_cache", {
                "service_id": args.get("serviceId"),
                "base_url": args.get("newBaseUrl"),
                "synced_at": "now()",
            })

    # ------------------------------------------------------------------
    # Default no-op callbacks (used when not connected to a real DB)
    # ------------------------------------------------------------------

    @staticmethod
    async def _noop_upsert(table: str, record: dict[str, Any]) -> None:
        logger.debug("noop upsert → %s: %s", table, record)

    @staticmethod
    async def _noop_get_block(contract_name: str) -> int:
        return 0

    @staticmethod
    async def _noop_save_block(contract_name: str, block: int) -> None:
        pass
