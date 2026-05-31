"""E2E conftest — fixtures that stand up the full Docker Compose stack."""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Generator

import httpx
import pytest
from web3 import Web3

COMPOSE_FILE = Path(__file__).parent / "docker-compose.e2e.yml"
DISCOVERY_URL = os.getenv("DISCOVERY_URL", "http://localhost:18000")
SENTINEL_PRODUCER_URL = os.getenv("SENTINEL_PRODUCER_URL", "http://localhost:18080")
SENTINEL_CONSUMER_URL = os.getenv("SENTINEL_CONSUMER_URL", "http://localhost:18081")
HARDHAT_URL = os.getenv("HARDHAT_URL", "http://localhost:18545")
VAULT_URL = os.getenv("VAULT_URL", "http://localhost:18200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "e2e-root-token")

# Used to skip the stack bring-up when running against an already-running stack.
USE_EXTERNAL_STACK = os.getenv("E2E_EXTERNAL_STACK", "false").lower() == "true"


# ── Stack lifecycle ───────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def stack() -> Generator[None, None, None]:
    """Bring up the E2E Docker Compose stack for the test session."""
    if USE_EXTERNAL_STACK:
        yield
        return

    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "build", "--quiet"],
        check=True,
    )
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d", "--wait"],
        check=True,
    )
    try:
        # Extra readiness wait for slow startup
        _wait_for(f"{DISCOVERY_URL}/health/ready", timeout=120)
        _wait_for(f"{SENTINEL_PRODUCER_URL}/health", timeout=120)
        yield
    finally:
        subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v", "--remove-orphans"],
            check=False,
        )


def _wait_for(url: str, timeout: int = 60, interval: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=5)
            if r.status_code < 500:
                return
        except Exception:
            pass
        time.sleep(interval)
    raise TimeoutError(f"Service at {url} did not become ready within {timeout}s")


# ── HTTP clients ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def discovery_client(stack: None) -> httpx.Client:
    with httpx.Client(base_url=DISCOVERY_URL, timeout=30) as client:
        yield client


@pytest.fixture(scope="session")
def sentinel_producer_client(stack: None) -> httpx.Client:
    with httpx.Client(base_url=SENTINEL_PRODUCER_URL, timeout=30) as client:
        yield client


@pytest.fixture(scope="session")
def sentinel_consumer_client(stack: None) -> httpx.Client:
    with httpx.Client(base_url=SENTINEL_CONSUMER_URL, timeout=30) as client:
        yield client


# ── Auth ──────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def admin_token(discovery_client: httpx.Client) -> str:
    """Obtain a short-lived admin JWT from the discovery service."""
    resp = discovery_client.post(
        "/api/v1/auth/token",
        json={"username": "admin", "password": os.getenv("E2E_ADMIN_PASSWORD", "admin")},
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


# ── Blockchain ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def hardhat(stack: None) -> Web3:
    w3 = Web3(Web3.HTTPProvider(HARDHAT_URL))
    assert w3.is_connected(), "Cannot connect to local hardhat node"
    return w3


@pytest.fixture(scope="session")
def deploy_contracts(hardhat: Web3, admin_token: str, discovery_client: httpx.Client) -> dict:
    """Deploy all registry contracts to the local chain and return their addresses."""
    resp = discovery_client.post(
        "/api/v1/admin/deploy-contracts",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"chain_id": 31337, "rpc_url": HARDHAT_URL},
    )
    resp.raise_for_status()
    return resp.json()["addresses"]
