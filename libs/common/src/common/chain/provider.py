"""AsyncWeb3 provider factory with reconnect middleware."""

from __future__ import annotations

import logging

from web3 import AsyncWeb3
from web3.middleware import ExtraDataToPOAMiddleware

logger = logging.getLogger(__name__)


async def create_web3(rpc_url: str) -> AsyncWeb3:
    """Create and validate an :class:`AsyncWeb3` connection.

    Supports:
    - ``http://`` / ``https://`` — uses :class:`~web3.providers.AsyncHTTPProvider`
    - ``ws://`` / ``wss://`` — uses :class:`~web3.providers.WebSocketProvider`

    Connectivity is validated by fetching the chain ID on startup.

    Args:
        rpc_url: Full RPC endpoint URL.

    Returns:
        Connected :class:`AsyncWeb3` instance.

    Raises:
        ValueError: If *rpc_url* scheme is not ``http``, ``https``, ``ws``, or ``wss``.
        Exception: If the provider is unreachable.
    """
    lower = rpc_url.lower()

    if lower.startswith("ws://") or lower.startswith("wss://"):
        from web3.providers import WebSocketProvider  # type: ignore[attr-defined]

        provider = WebSocketProvider(rpc_url)
        web3 = AsyncWeb3(provider)
    elif lower.startswith("http://") or lower.startswith("https://"):
        from web3.providers import AsyncHTTPProvider

        provider = AsyncHTTPProvider(
            rpc_url,
            request_kwargs={"timeout": 30},
        )
        web3 = AsyncWeb3(provider)
    else:
        raise ValueError(
            f"Unsupported RPC URL scheme: {rpc_url!r}. "
            "Expected http://, https://, ws://, or wss://."
        )

    # Inject PoA middleware for networks that return extra fields (e.g. Hardhat)
    web3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    # Validate connectivity
    chain_id = await web3.eth.chain_id
    logger.info("Connected to chain %d via %s", chain_id, rpc_url)
    return web3
