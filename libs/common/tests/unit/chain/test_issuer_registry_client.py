"""Unit tests for IssuerRegistryClient.

Uses unittest.mock.AsyncMock to simulate the web3 contract interface
without needing a live node.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from common.chain.clients.issuer_registry import IssuerRegistryClient, IssuerRecordModel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_client(call_return_value=None, transact_return_value=None):
    """Build an IssuerRegistryClient with mocked async methods."""
    web3 = MagicMock()
    address = "0x" + "a" * 40
    abi = []  # not used by mocked base

    client = IssuerRegistryClient(web3=web3, address=address, abi=abi)

    # Patch ContractClient low-level helpers
    client.async_call = AsyncMock(return_value=call_return_value)
    client.async_transact = AsyncMock(return_value=transact_return_value)
    return client


# ---------------------------------------------------------------------------
# is_issuer_active
# ---------------------------------------------------------------------------

class TestIsIssuerActive:
    @pytest.mark.asyncio
    async def test_returns_true_when_active(self):
        client = _make_client(call_return_value=True)
        result = await client.is_issuer_active("did:example:123")
        assert result is True
        client.async_call.assert_called_once_with("isIssuerActive", "did:example:123")

    @pytest.mark.asyncio
    async def test_returns_false_when_inactive(self):
        client = _make_client(call_return_value=False)
        result = await client.is_issuer_active("did:example:revoked")
        assert result is False


# ---------------------------------------------------------------------------
# get_issuer
# ---------------------------------------------------------------------------

class TestGetIssuer:
    @pytest.mark.asyncio
    async def test_returns_model_on_success(self):
        raw = (
            "did:example:abc",  # did / did_hash placeholder
            "Acme Corp",        # name
            "A test issuer",    # description
            1_700_000_000,      # registered_at (unix)
            1_700_000_001,      # updated_at (unix)
            True,               # active
            "https://acme.example/meta.json",  # metadata_uri
        )
        client = _make_client(call_return_value=raw)
        record = await client.get_issuer("did:example:abc")
        assert isinstance(record, IssuerRecordModel)
        assert record.name == "Acme Corp"
        assert record.active is True
        assert record.metadata_uri == "https://acme.example/meta.json"

    @pytest.mark.asyncio
    async def test_returns_none_on_exception(self):
        client = _make_client()
        client.async_call = AsyncMock(side_effect=Exception("revert"))
        result = await client.get_issuer("did:example:missing")
        assert result is None


# ---------------------------------------------------------------------------
# get_issuer_count
# ---------------------------------------------------------------------------

class TestGetIssuerCount:
    @pytest.mark.asyncio
    async def test_returns_int(self):
        client = _make_client(call_return_value=7)
        count = await client.get_issuer_count()
        assert count == 7

    @pytest.mark.asyncio
    async def test_coerces_string_to_int(self):
        # Some ABI decoders may return large ints as strings
        client = _make_client(call_return_value="42")
        count = await client.get_issuer_count()
        assert count == 42


# ---------------------------------------------------------------------------
# register_issuer
# ---------------------------------------------------------------------------

class TestRegisterIssuer:
    @pytest.mark.asyncio
    async def test_calls_transact(self):
        receipt = {"status": 1, "transactionHash": b"\xab" * 32}
        client = _make_client(transact_return_value=receipt)
        result = await client.register_issuer(
            "did:example:new",
            "New Corp",
            "desc",
            "https://meta.example",
            private_key="0x" + "b" * 64,
        )
        assert result == receipt
        client.async_transact.assert_called_once_with(
            "registerIssuer",
            "did:example:new",
            "New Corp",
            "desc",
            "https://meta.example",
            private_key="0x" + "b" * 64,
        )
