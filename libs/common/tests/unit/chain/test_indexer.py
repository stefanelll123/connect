"""Unit tests for ChainEventIndexer."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call
import pytest

from common.chain.indexer import ChainEventIndexer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_indexer(upserts: list | None = None, last_blocks: dict | None = None, saved_blocks: list | None = None):
    """Return an indexer with in-memory upsert / block-state callbacks."""
    upsert_log: list = upserts if upserts is not None else []
    block_state: dict = last_blocks if last_blocks is not None else {}
    save_log: list = saved_blocks if saved_blocks is not None else []

    async def _upsert(table: str, record: dict) -> None:
        upsert_log.append((table, record))

    async def _get_block(name: str) -> int:
        return block_state.get(name, 0)

    async def _save_block(name: str, block: int) -> None:
        save_log.append((name, block))
        block_state[name] = block

    web3 = MagicMock()
    web3.eth.get_block_number = AsyncMock(return_value=100)

    return ChainEventIndexer(
        web3=web3,
        contracts={},
        poll_interval=0,
        upsert_fn=_upsert,
        get_last_block_fn=_get_block,
        save_last_block_fn=_save_block,
    ), upsert_log, save_log, web3


# ---------------------------------------------------------------------------
# run() / stop()
# ---------------------------------------------------------------------------

class TestRunStop:
    @pytest.mark.asyncio
    async def test_stop_exits_loop(self):
        indexer, _, _, web3 = _make_indexer()
        web3.eth.get_block_number = AsyncMock(return_value=10)  # override for this test

        # Run for one iteration then stop
        async def _stopper():
            await asyncio.sleep(0.01)
            indexer.stop()

        await asyncio.gather(indexer.run(), _stopper())
        assert not indexer._running

    @pytest.mark.asyncio
    async def test_poll_error_does_not_crash_loop(self, monkeypatch):
        """A poll cycle exception should be swallowed (logged) and loop continues."""
        indexer, _, _, web3 = _make_indexer()
        call_count = 0

        async def _bad_poll():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("simulated network error")
            indexer.stop()

        monkeypatch.setattr(indexer, "_poll_all", _bad_poll)
        await indexer.run()
        assert call_count == 2  # ran twice despite error on first


# ---------------------------------------------------------------------------
# _poll_all — block range logic
# ---------------------------------------------------------------------------

class TestPollAll:
    @pytest.mark.asyncio
    async def test_skips_contract_if_already_at_tip(self):
        web3 = MagicMock()
        web3.eth.get_block_number = AsyncMock(return_value=50)

        block_state = {"IssuerRegistry": 50}  # already at tip
        save_log: list = []
        upsert_log: list = []

        async def _get_block(name: str) -> int:
            return block_state.get(name, 0)

        async def _save_block(name: str, block: int) -> None:
            save_log.append((name, block))

        mock_contract = MagicMock()

        indexer = ChainEventIndexer(
            web3=web3,
            contracts={"IssuerRegistry": mock_contract},
            poll_interval=0,
            get_last_block_fn=_get_block,
            save_last_block_fn=_save_block,
        )

        await indexer._poll_all()
        assert save_log == []  # nothing saved because already at latest

    @pytest.mark.asyncio
    async def test_saves_last_block_after_processing(self):
        web3 = MagicMock()
        web3.eth.get_block_number = AsyncMock(return_value=200)

        save_log: list = []

        async def _get_block(name: str) -> int:
            return 100

        async def _save_block(name: str, block: int) -> None:
            save_log.append((name, block))

        mock_contract = MagicMock()

        indexer = ChainEventIndexer(
            web3=web3,
            contracts={"ServiceRegistry": mock_contract},
            poll_interval=0,
            get_last_block_fn=_get_block,
            save_last_block_fn=_save_block,
        )
        # _process_contract raises because contract has no allEvents; suppress
        with patch.object(indexer, "_process_contract", new_callable=AsyncMock):
            await indexer._poll_all()

        assert ("ServiceRegistry", 200) in save_log


# ---------------------------------------------------------------------------
# Individual event handlers
# ---------------------------------------------------------------------------

class TestIssuerEventHandlers:
    @pytest.mark.asyncio
    async def test_issuer_registered_upserts_active(self):
        indexer, upsert_log, _, _ = _make_indexer()
        event = {
            "event": "IssuerRegistered",
            "args": {"did": "did:example:abc", "didHash": b"\x00" * 32, "name": "ACME"},
        }
        await indexer._handle_issuer_events(event)
        assert len(upsert_log) == 1
        table, record = upsert_log[0]
        assert table == "issuers_cache"
        assert record["active"] is True
        assert record["did"] == "did:example:abc"

    @pytest.mark.asyncio
    async def test_issuer_revoked_upserts_inactive(self):
        indexer, upsert_log, _, _ = _make_indexer()
        event = {
            "event": "IssuerRevoked",
            "args": {"did": "did:example:gone", "didHash": b"\xff" * 32},
        }
        await indexer._handle_issuer_events(event)
        table, record = upsert_log[0]
        assert record["active"] is False


class TestPolicyEventHandlers:
    @pytest.mark.asyncio
    async def test_policy_created_upserts(self):
        indexer, upsert_log, _, _ = _make_indexer()
        event = {
            "event": "PolicyCreated",
            "args": {"serviceId": "svc-1", "version": 1},
        }
        await indexer._handle_policy_events(event)
        table, record = upsert_log[0]
        assert table == "trust_policies_cache"
        assert record["service_id"] == "svc-1"
        assert record["active"] is True

    @pytest.mark.asyncio
    async def test_policy_deactivated_upserts_inactive(self):
        indexer, upsert_log, _, _ = _make_indexer()
        event = {"event": "PolicyDeactivated", "args": {"serviceId": "svc-2"}}
        await indexer._handle_policy_events(event)
        _, record = upsert_log[0]
        assert record["active"] is False


class TestStatusEventHandlers:
    @pytest.mark.asyncio
    async def test_status_anchor_published(self):
        indexer, upsert_log, _, _ = _make_indexer()
        event = {
            "event": "StatusAnchorPublished",
            "args": {
                "issuerDidHash": b"\xab" * 32,
                "statusListIndex": 7,
                "credentialHash": b"\xcd" * 32,
                "statusListUrl": "https://status.example/list.jwt",
                "freshnessDeltaSeconds": 3600,
            },
        }
        await indexer._handle_status_events(event)
        table, record = upsert_log[0]
        assert table == "status_anchors_cache"
        assert record["status_list_index"] == 7
        assert record["freshness_delta_seconds"] == 3600


class TestServiceEventHandlers:
    @pytest.mark.asyncio
    async def test_service_registered_upserts_active(self):
        indexer, upsert_log, _, _ = _make_indexer()
        event = {
            "event": "ServiceRegistered",
            "args": {
                "serviceId": "svc-10",
                "did": "did:example:svc",
                "baseUrl": "https://svc.example",
                "role": "VERIFIER_ROLE",
            },
        }
        await indexer._handle_service_events(event)
        table, record = upsert_log[0]
        assert table == "services_cache"
        assert record["active"] is True

    @pytest.mark.asyncio
    async def test_service_deregistered_upserts_inactive(self):
        indexer, upsert_log, _, _ = _make_indexer()
        event = {"event": "ServiceDeregistered", "args": {"serviceId": "svc-10"}}
        await indexer._handle_service_events(event)
        _, record = upsert_log[0]
        assert record["active"] is False


# ---------------------------------------------------------------------------
# Nonce lock test (regression guard)
# ---------------------------------------------------------------------------

class TestNopCallbacks:
    """Verify the no-op defaults don't raise and return expected sentinel values."""

    @pytest.mark.asyncio
    async def test_noop_get_block_returns_zero(self):
        result = await ChainEventIndexer._noop_get_block("IssuerRegistry")
        assert result == 0

    @pytest.mark.asyncio
    async def test_noop_save_block_returns_none(self):
        result = await ChainEventIndexer._noop_save_block("IssuerRegistry", 999)
        assert result is None

    @pytest.mark.asyncio
    async def test_noop_upsert_returns_none(self):
        result = await ChainEventIndexer._noop_upsert("some_table", {"key": "value"})
        assert result is None
