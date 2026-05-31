"""ChainClient — async web3.py wrapper for the Discovery Service (TASK-031).

Provides a thin async interface over web3.py's AsyncWeb3:
  - get_block_number()   → current head block
  - get_logs()           → decoded contract events for a block range
  - call()               → read-only contract function call

Registry clients (IssuerRegistryClient, TrustPolicyRegistryClient,
StatusRegistryClient) are built on top of ChainClient using the minimal
ABIs defined here as module-level constants.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from web3 import AsyncHTTPProvider, AsyncWeb3
from web3.exceptions import ContractLogicError

logger = logging.getLogger(__name__)


def _sanitize_event_args(args: dict) -> dict:
    """Convert bytes/HexBytes values to hex strings so the dict is JSON-serializable."""
    return {k: (v.hex() if isinstance(v, bytes) else v) for k, v in args.items()}


# ---------------------------------------------------------------------------
# Minimal ABIs — only the events and functions we actually call
# ---------------------------------------------------------------------------

ISSUER_REGISTRY_ABI: list[dict] = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "didHash", "type": "bytes32"},
            {"indexed": False, "name": "did", "type": "string"},
            {"indexed": False, "name": "name", "type": "string"},
            {"indexed": True, "name": "registeredBy", "type": "address"},
        ],
        "name": "IssuerRegistered",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "didHash", "type": "bytes32"},
            {"indexed": False, "name": "did", "type": "string"},
            {"indexed": True, "name": "revokedBy", "type": "address"},
        ],
        "name": "IssuerRevoked",
        "type": "event",
    },
    {
        "inputs": [],
        "name": "getIssuerCount",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "index", "type": "uint256"}],
        "name": "getIssuerAtIndex",
        "outputs": [
            {
                "components": [
                    {"name": "did", "type": "string"},
                    {"name": "name", "type": "string"},
                    {"name": "description", "type": "string"},
                    {"name": "registeredAt", "type": "uint256"},
                    {"name": "updatedAt", "type": "uint256"},
                    {"name": "active", "type": "bool"},
                    {"name": "metadataURI", "type": "string"},
                ],
                "internalType": "struct IIssuerRegistry.IssuerRecord",
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "did", "type": "string"}],
        "name": "isIssuerActive",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "did", "type": "string"},
            {"name": "name", "type": "string"},
            {"name": "description", "type": "string"},
            {"name": "metadataURI", "type": "string"},
        ],
        "name": "registerIssuer",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]

TRUST_POLICY_REGISTRY_ABI: list[dict] = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "policyId", "type": "bytes32"},
            {"indexed": True, "name": "createdBy", "type": "address"},
        ],
        "name": "PolicyCreated",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "policyId", "type": "bytes32"},
            {"indexed": True, "name": "updatedBy", "type": "address"},
        ],
        "name": "PolicyUpdated",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "policyId", "type": "bytes32"},
            {"indexed": True, "name": "deactivatedBy", "type": "address"},
        ],
        "name": "PolicyDeactivated",
        "type": "event",
    },
    {
        "inputs": [],
        "name": "getPolicyCount",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
]

STATUS_REGISTRY_ABI: list[dict] = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "issuerDid", "type": "string"},
            {"indexed": True, "name": "statusListIndex", "type": "uint256"},
            {"indexed": False, "name": "credentialHash", "type": "bytes32"},
            {"indexed": False, "name": "statusListUrl", "type": "string"},
            {"indexed": False, "name": "freshnessDeltaSeconds", "type": "uint256"},
            {"indexed": False, "name": "publishedAt", "type": "uint256"},
        ],
        "name": "StatusAnchorPublished",
        "type": "event",
    },
    {
        "inputs": [
            {"name": "issuerDid", "type": "string"},
            {"name": "statusListIndex", "type": "uint256"},
            {"name": "credentialHash", "type": "bytes32"},
            {"name": "statusListUrl", "type": "string"},
            {"name": "freshnessDeltaSeconds", "type": "uint256"},
        ],
        "name": "publishStatusAnchor",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]

SERVICE_REGISTRY_ABI: list[dict] = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "serviceIdHash", "type": "bytes32"},
            {"indexed": False, "name": "serviceId", "type": "string"},
            {"indexed": False, "name": "did", "type": "string"},
            {"indexed": False, "name": "role", "type": "string"},
            {"indexed": False, "name": "baseUrl", "type": "string"},
        ],
        "name": "ServiceRegistered",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "serviceIdHash", "type": "bytes32"},
            {"indexed": False, "name": "serviceId", "type": "string"},
            {"indexed": False, "name": "newBaseUrl", "type": "string"},
        ],
        "name": "ServiceUpdated",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "serviceIdHash", "type": "bytes32"},
            {"indexed": False, "name": "serviceId", "type": "string"},
        ],
        "name": "ServiceDeregistered",
        "type": "event",
    },
    {
        "inputs": [
            {"name": "serviceId", "type": "string"},
            {"name": "did", "type": "string"},
            {"name": "baseUrl", "type": "string"},
            {"name": "role", "type": "string"},
            {"name": "description", "type": "string"},
        ],
        "name": "registerService",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
]


# ---------------------------------------------------------------------------
# ChainClient
# ---------------------------------------------------------------------------


class ChainClient:
    """Async web3.py wrapper.  One instance per application."""

    def __init__(self, rpc_url: str, timeout_seconds: int = 10) -> None:
        self._w3 = AsyncWeb3(
            AsyncHTTPProvider(rpc_url, request_kwargs={"timeout": timeout_seconds})
        )

    async def get_block_number(self) -> int:
        return await self._w3.eth.block_number

    async def get_logs(
        self,
        *,
        address: str,
        abi: list[dict],
        from_block: int,
        to_block: int,
    ) -> list[dict]:
        """Fetch and decode all watched events from *address* over the block range.

        Returns a list of dicts::

            {"tx_hash": str, "block_number": int, "event_name": str, "args": dict}
        """
        checksum_addr = AsyncWeb3.to_checksum_address(address)
        contract = self._w3.eth.contract(address=checksum_addr, abi=abi)
        results: list[dict] = []

        for entry in abi:
            if entry.get("type") != "event":
                continue
            event_name: str = entry["name"]
            event_cls = getattr(contract.events, event_name, None)
            if event_cls is None:
                continue
            try:
                logs = await event_cls.get_logs(
                    from_block=from_block, to_block=to_block
                )
                for log in logs:
                    results.append(
                        {
                            "tx_hash": log["transactionHash"].hex(),
                            "block_number": int(log["blockNumber"]),
                            "event_name": event_name,
                            "args": _sanitize_event_args(dict(log["args"])),
                        }
                    )
            except Exception as exc:
                logger.warning(
                    "get_logs error for %s [%s]: %s", event_name, address, exc
                )
        return results

    async def call(self, *, address: str, abi: list[dict], fn: str, args: tuple = ()) -> Any:
        """Call a view/pure function on *address*."""
        checksum_addr = AsyncWeb3.to_checksum_address(address)
        contract = self._w3.eth.contract(address=checksum_addr, abi=abi)
        fn_obj = contract.functions[fn]
        return await fn_obj(*args).call()

    async def send_transaction(
        self,
        *,
        address: str,
        abi: list[dict],
        fn: str,
        args: tuple = (),
        private_key: str,
    ) -> str:
        """Build, sign and send a transaction.  Returns tx_hash hex string."""
        checksum_addr = AsyncWeb3.to_checksum_address(address)
        contract = self._w3.eth.contract(address=checksum_addr, abi=abi)
        account = self._w3.eth.account.from_key(private_key)
        nonce = await self._w3.eth.get_transaction_count(account.address)
        tx = await contract.functions[fn](*args).build_transaction(
            {
                "from": account.address,
                "nonce": nonce,
                "chainId": await self._w3.eth.chain_id,
            }
        )
        signed = account.sign_transaction(tx)
        tx_hash = await self._w3.eth.send_raw_transaction(signed.raw_transaction)
        await self._w3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash.hex()


# ---------------------------------------------------------------------------
# Registry clients
# ---------------------------------------------------------------------------


class IssuerRegistryClient:
    def __init__(self, chain: ChainClient, address: str) -> None:
        self._chain = chain
        self._address = address

    async def get_all_issuers(self) -> list[dict]:
        """Return list of IssuerRecord dicts with keys: did, active."""
        count: int = await self._chain.call(
            address=self._address,
            abi=ISSUER_REGISTRY_ABI,
            fn="getIssuerCount",
        )
        issuers: list[dict] = []
        for i in range(int(count)):
            rec = await self._chain.call(
                address=self._address,
                abi=ISSUER_REGISTRY_ABI,
                fn="getIssuerAtIndex",
                args=(i,),
            )
            issuers.append({"did": rec[0], "active": rec[5]})
        return issuers

    async def is_issuer_active(self, did: str) -> bool:
        return await self._chain.call(
            address=self._address,
            abi=ISSUER_REGISTRY_ABI,
            fn="isIssuerActive",
            args=(did,),
        )

    async def register_issuer(
        self,
        did: str,
        name: str,
        description: str,
        anchor_key: str,
        metadata_uri: str = "",
    ) -> str:
        """Call registerIssuer on-chain.  Returns tx_hash hex string.

        Requires the *anchor_key* account to hold ISSUER_ADMIN_ROLE.
        """
        return await self._chain.send_transaction(
            address=self._address,
            abi=ISSUER_REGISTRY_ABI,
            fn="registerIssuer",
            args=(did, name, description, metadata_uri),
            private_key=anchor_key,
        )


class TrustPolicyRegistryClient:
    def __init__(self, chain: ChainClient, address: str) -> None:
        self._chain = chain
        self._address = address

    async def get_policy_count(self) -> int:
        return int(
            await self._chain.call(
                address=self._address,
                abi=TRUST_POLICY_REGISTRY_ABI,
                fn="getPolicyCount",
            )
        )


class StatusRegistryClient:
    def __init__(self, chain: ChainClient, address: str, private_key: str) -> None:
        self._chain = chain
        self._address = address
        self._private_key = private_key

    async def publish_status_anchor(
        self,
        *,
        issuer_did: str,
        status_list_index: int,
        credential_hash: bytes,
        status_list_url: str,
        freshness_delta_seconds: int = 3600,
    ) -> str:
        """Call StatusRegistry.publishStatusAnchor().  Returns tx_hash."""
        # credential_hash must be exactly 32 bytes
        hash_b32 = credential_hash[:32].ljust(32, b"\x00")
        hash_padded = bytes(hash_b32)
        return await self._chain.send_transaction(
            address=self._address,
            abi=STATUS_REGISTRY_ABI,
            fn="publishStatusAnchor",
            args=(
                issuer_did,
                status_list_index,
                hash_padded,
                status_list_url,
                freshness_delta_seconds,
            ),
            private_key=self._private_key,
        )


class ServiceRegistryClient:
    def __init__(self, chain: ChainClient, address: str, private_key: str) -> None:
        self._chain = chain
        self._address = address
        self._private_key = private_key

    async def register_service(
        self,
        *,
        service_id: str,
        did: str,
        base_url: str = "",
        role: str = "producer",
        description: str = "",
    ) -> str:
        """Call ServiceRegistry.registerService().  Returns tx_hash."""
        return await self._chain.send_transaction(
            address=self._address,
            abi=SERVICE_REGISTRY_ABI,
            fn="registerService",
            args=(service_id, did, base_url, role, description),
            private_key=self._private_key,
        )
