"""ContractClient base class — async read/write wrappers for a single contract."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from eth_account import Account
from eth_typing import ChecksumAddress
from web3 import AsyncWeb3
from web3.types import TxReceipt

logger = logging.getLogger(__name__)

# Per-sender nonce locks: sender_address → asyncio.Lock
_NONCE_LOCKS: dict[str, asyncio.Lock] = {}
_LOCKS_MUTEX = asyncio.Lock()


async def _get_nonce_lock(sender: str) -> asyncio.Lock:
    """Return (creating if needed) the nonce lock for *sender*."""
    async with _LOCKS_MUTEX:
        if sender not in _NONCE_LOCKS:
            _NONCE_LOCKS[sender] = asyncio.Lock()
        return _NONCE_LOCKS[sender]


class ContractClient:
    """Async wrapper around a single deployed smart contract.

    Provides:
    - :meth:`async_call` — read-only ``eth_call`` (no gas spent)
    - :meth:`async_transact` — state-changing signed transaction with EIP-1559
      gas estimation and nonce management.
    """

    def __init__(
        self,
        web3: AsyncWeb3,
        address: ChecksumAddress,
        abi: list[Any],
    ) -> None:
        self._web3 = web3
        self._address = address
        self._contract = web3.eth.contract(address=address, abi=abi)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def async_call(self, fn_name: str, *args: Any) -> Any:
        """Execute a read-only contract call.

        Args:
            fn_name: Solidity function name.
            *args:   Positional arguments forwarded to the function.

        Returns:
            The decoded return value(s) from the contract function.
        """
        fn = self._contract.functions[fn_name](*args)
        return await fn.call()

    async def async_transact(
        self,
        fn_name: str,
        *args: Any,
        private_key: str,
    ) -> TxReceipt:
        """Build, sign, broadcast and await a state-changing transaction.

        Uses EIP-1559 gas pricing. A per-sender asyncio lock guards the
        get-nonce → submit sequence to prevent nonce collisions in concurrent
        callers.

        Args:
            fn_name:     Solidity function name.
            *args:       Positional arguments forwarded to the function.
            private_key: Hex-encoded private key (``0x...``) for the sender EOA.
                         **Never log the value of this parameter.**

        Returns:
            Mined transaction receipt.

        Raises:
            Exception: On transaction failure or replacement underpriced (after
                       one retry with 1.1× gas bump).
        """
        account = Account.from_key(private_key)
        sender = account.address
        lock = await _get_nonce_lock(sender)

        async with lock:
            nonce = await self._web3.eth.get_transaction_count(sender, "pending")
            fn = self._contract.functions[fn_name](*args)

            # EIP-1559 gas estimation
            base_fee = (await self._web3.eth.get_block("latest"))["baseFeePerGas"]
            max_priority_fee = await self._web3.eth.max_priority_fee
            max_fee = base_fee * 2 + max_priority_fee

            tx_params = {
                "from": sender,
                "nonce": nonce,
                "maxFeePerGas": max_fee,
                "maxPriorityFeePerGas": max_priority_fee,
            }
            gas_estimate = await fn.estimate_gas(tx_params)
            tx_params["gas"] = int(gas_estimate * 1.2)  # 20% buffer

            tx = await fn.build_transaction(tx_params)
            signed = account.sign_transaction(tx)

            try:
                tx_hash = await self._web3.eth.send_raw_transaction(signed.raw_transaction)
            except Exception as exc:
                # One retry with 1.1× gas bump for replacement-underpriced errors
                if "replacement transaction underpriced" in str(exc).lower():
                    logger.warning("Replacement transaction underpriced — retrying with 1.1× gas")
                    tx_params["maxFeePerGas"] = int(max_fee * 1.1)
                    tx_params["maxPriorityFeePerGas"] = int(max_priority_fee * 1.1)
                    tx = await fn.build_transaction(tx_params)
                    signed = account.sign_transaction(tx)
                    tx_hash = await self._web3.eth.send_raw_transaction(signed.raw_transaction)
                else:
                    raise

        return await self._web3.eth.wait_for_transaction_receipt(tx_hash)
