"""Unit tests for sentinelctl status and rejoin commands (TASK-049).

Tests:
  1. status exits 0 when Discovery responds OK
  2. status exits 1 when Discovery is unreachable
  3. status shows instance_id, DID, key_mode fields
  4. rejoin exits 0 on HTTP 200 from Discovery
  5. rejoin exits 0 on HTTP 409 (already registered — idempotent)
  6. rejoin exits 1 when challenge request fails
"""
from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from sentinel.cli.sentinelctl import app
from sentinel.wallet.key_manager import Wallet, generate_ed25519_keypair, derive_did_key

runner = CliRunner()

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def initialized_store(tmp_path):
    """Return a path to an initialized sentinel wallet store."""
    store = tmp_path / "store"
    wallet = Wallet(store)
    os.environ["SENTINEL_PASSPHRASE"] = "test-passphrase"
    wallet.init(
        service_id="test-svc",
        role="producer",
        env="dev",
        passphrase=b"test-passphrase",
    )
    yield store
    os.environ.pop("SENTINEL_PASSPHRASE", None)


# ---------------------------------------------------------------------------
# Test 1: status exits 0 when Discovery is healthy
# ---------------------------------------------------------------------------


class TestStatusCommand:
    def test_exits_0_when_all_green(self, initialized_store, tmp_path):
        sentinel_home = str(tmp_path)
        # Write an instance_id file
        (tmp_path / "instance_id").write_text(str(uuid.uuid4()))

        with patch("httpx.get") as mock_get, patch("httpx.post") as mock_post:
            mock_get.return_value = MagicMock(status_code=200)
            mock_post.return_value = MagicMock(
                status_code=200, json=lambda: {"result": "0x123"}
            )
            result = runner.invoke(
                app,
                [
                    "status",
                    "--store", str(initialized_store),
                    "--discovery-url", "http://localhost:8000",
                    "--chain-rpc-url", "http://localhost:8545",
                    "--sentinel-home", sentinel_home,
                ],
            )

        assert result.exit_code == 0
        assert "instance_id" in result.output
        assert "discovery" in result.output
        assert "✓ online" in result.output

    def test_exits_1_when_discovery_down(self, initialized_store, tmp_path):
        sentinel_home = str(tmp_path)
        (tmp_path / "instance_id").write_text(str(uuid.uuid4()))

        with patch("httpx.get", side_effect=Exception("connection refused")):
            with patch("httpx.post", side_effect=Exception("connection refused")):
                result = runner.invoke(
                    app,
                    [
                        "status",
                        "--store", str(initialized_store),
                        "--discovery-url", "http://localhost:8000",
                        "--chain-rpc-url", "http://localhost:8545",
                        "--sentinel-home", sentinel_home,
                    ],
                )

        assert result.exit_code == 1
        assert "✗ unreachable" in result.output
        assert "sentinel_operational: false" in result.output

    def test_shows_did_and_key_mode(self, initialized_store, tmp_path):
        sentinel_home = str(tmp_path)
        (tmp_path / "instance_id").write_text(str(uuid.uuid4()))

        with patch("httpx.get") as mock_get, patch("httpx.post") as mock_post:
            mock_get.return_value = MagicMock(status_code=200)
            mock_post.return_value = MagicMock(
                status_code=200, json=lambda: {"result": "0x1"}
            )
            result = runner.invoke(
                app,
                [
                    "status",
                    "--store", str(initialized_store),
                    "--discovery-url", "http://localhost:8000",
                    "--chain-rpc-url", "http://localhost:8545",
                    "--sentinel-home", sentinel_home,
                ],
            )

        assert "did:key:" in result.output
        assert "key_mode" in result.output


# ---------------------------------------------------------------------------
# Test 4 & 5: rejoin exits 0 on HTTP 200 / 409
# ---------------------------------------------------------------------------


class TestRejoinCommand:
    def _mock_challenge_resp(self):
        return MagicMock(
            status_code=200,
            json=lambda: {"nonce": "test-nonce-123", "enrollment_token": "tok-abc"},
        )

    def _mock_complete_resp(self, status_code: int):
        return MagicMock(status_code=status_code, text="ok")

    def test_exits_0_on_http_200(self, initialized_store, tmp_path):
        os.environ["SENTINEL_PASSPHRASE"] = "test-passphrase"

        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = lambda _: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = [
                self._mock_challenge_resp(),
                self._mock_complete_resp(200),
            ]

            result = runner.invoke(
                app,
                [
                    "rejoin",
                    "--store", str(initialized_store),
                    "--discovery-url", "http://discovery:8000",
                    "--service-id", "test-svc",
                    "--endpoint-url", "https://sentinel.internal:8443",
                ],
                env={"SENTINEL_PASSPHRASE": "test-passphrase"},
            )

        assert result.exit_code == 0, result.output
        assert "successful" in result.output.lower() or "Rejoin" in result.output

    def test_exits_0_on_http_409_already_registered(self, initialized_store, tmp_path):
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = lambda _: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = [
                self._mock_challenge_resp(),
                self._mock_complete_resp(409),
            ]

            result = runner.invoke(
                app,
                [
                    "rejoin",
                    "--store", str(initialized_store),
                    "--discovery-url", "http://discovery:8000",
                    "--service-id", "test-svc",
                ],
                env={"SENTINEL_PASSPHRASE": "test-passphrase"},
            )

        assert result.exit_code == 0
        assert "idempotent" in result.output.lower() or "already registered" in result.output.lower()

    def test_exits_1_when_challenge_fails(self, initialized_store, tmp_path):
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = lambda _: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = Exception("connection refused")

            result = runner.invoke(
                app,
                [
                    "rejoin",
                    "--store", str(initialized_store),
                    "--discovery-url", "http://discovery:8000",
                    "--service-id", "test-svc",
                ],
                env={"SENTINEL_PASSPHRASE": "test-passphrase"},
            )

        assert result.exit_code == 1
        assert "cannot reach Discovery" in result.output or "Error" in result.output

    def test_exits_1_when_complete_returns_500(self, initialized_store, tmp_path):
        with patch("httpx.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value.__enter__ = lambda _: mock_client
            mock_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = [
                self._mock_challenge_resp(),
                MagicMock(status_code=500, text='{"error": "internal"}'),
            ]

            result = runner.invoke(
                app,
                [
                    "rejoin",
                    "--store", str(initialized_store),
                    "--discovery-url", "http://discovery:8000",
                    "--service-id", "test-svc",
                ],
                env={"SENTINEL_PASSPHRASE": "test-passphrase"},
            )

        assert result.exit_code == 1
