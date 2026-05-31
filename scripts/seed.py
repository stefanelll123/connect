#!/usr/bin/env python3
"""Local development seed script.

Three phases:
  Phase 1 (chain)  — Deploy all 4 registry contracts to the local Anvil node
                     and write contracts/deployments/local.json.
  Phase 2 (db)     — Insert bootstrap metadata into PostgreSQL via asyncpg.
  Phase 3 (service)— Verify Discovery Service health.
                     Full sentinel onboarding is implemented in TASK-021+.

Usage:
    python scripts/seed.py                   # all phases
    python scripts/seed.py --chain-only      # Phase 1 only
    python scripts/seed.py --db-only         # Phases 2+3 only (re-uses existing deployments/local.json)
    python scripts/seed.py --skip-chain      # Phases 2+3 with addresses from existing deployments/local.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import asyncpg
import httpx
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

# ---------------------------------------------------------------------------
# Configuration (resolved from environment at startup)
# ---------------------------------------------------------------------------
RPC_URL = os.getenv("BLOCKCHAIN_RPC_URL", "http://localhost:8545")
DATABASE_URL = os.getenv("DATABASE_URL", "")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "")
DISCOVERY_URL = os.getenv("DISCOVERY_URL", "http://localhost:8000")
ADMIN_API_KEY = os.getenv("DISCOVERY_ADMIN_API_KEY", "changeme_admin_key_local_only")

# Anvil first pre-funded account (deterministic, dev-only, safe for local use)
_ANVIL_DEFAULT_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEPLOYER_KEY = os.getenv("HARDHAT_PRIVATE_KEY", _ANVIL_DEFAULT_KEY)

ROOT = Path(__file__).parent.parent
ARTIFACTS_DIR = ROOT / "contracts" / "artifacts" / "contracts" / "Registries"
DEPLOYMENTS_DIR = ROOT / "contracts" / "deployments"

REGISTRY_NAMES = [
    "IssuerRegistry",
    "TrustPolicyRegistry",
    "StatusRegistry",
    "ServiceRegistry",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_artifact(name: str) -> dict:
    """Load Hardhat artifact JSON (contains ABI + bytecode)."""
    path = ARTIFACTS_DIR / f"{name}.sol" / f"{name}.json"
    if not path.exists():
        print(f"  ✗ Artifact not found: {path}", file=sys.stderr)
        print("    Run 'make contracts-compile' first.", file=sys.stderr)
        sys.exit(1)
    with path.open() as f:
        return json.load(f)


def _wait_for_node(w3: Web3, max_attempts: int = 30) -> None:
    for attempt in range(max_attempts):
        try:
            if w3.is_connected():
                print(f"  ✓ Anvil node ready (attempt {attempt + 1})")
                return
        except Exception:
            pass
        time.sleep(2)
    print("  ✗ Anvil node did not become ready within timeout.", file=sys.stderr)
    sys.exit(1)


def _build_dsn() -> str:
    """Return a plain asyncpg DSN (no +asyncpg driver prefix)."""
    if DATABASE_URL:
        dsn = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://", 1)
        return dsn
    if not POSTGRES_PASSWORD:
        print("  ✗ POSTGRES_PASSWORD is not set and DATABASE_URL is empty.", file=sys.stderr)
        sys.exit(1)
    return f"postgresql://sentinel_user:{POSTGRES_PASSWORD}@localhost:5432/sentinel_db"


# ---------------------------------------------------------------------------
# Phase 1: deploy contracts
# ---------------------------------------------------------------------------

def run_phase1_chain() -> dict:
    print("\n[Phase 1] Deploying contracts to local Anvil node …")

    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    _wait_for_node(w3)

    deployer = w3.eth.account.from_key(DEPLOYER_KEY)
    w3.eth.default_account = deployer.address
    print(f"  Deployer : {deployer.address}")
    print(f"  Chain ID : {w3.eth.chain_id}")

    deployed: dict[str, dict] = {}
    for name in REGISTRY_NAMES:
        print(f"  Deploying {name} …", end=" ", flush=True)
        artifact = _load_artifact(name)
        contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])
        # All registry constructors accept (address initialOwner) — OZ Ownable v5
        tx = contract.constructor(deployer.address).transact(
            {"from": deployer.address, "gas": 3_000_000}
        )
        receipt = w3.eth.wait_for_transaction_receipt(tx)
        print(f"→ {receipt.contractAddress}  (block {receipt.blockNumber})")
        deployed[name] = {
            "address": receipt.contractAddress,
            "deployedBlock": receipt.blockNumber,
            "txHash": tx.hex(),
        }

    output = {
        "network": "local",
        "chainId": int(w3.eth.chain_id),
        "deployedAt": datetime.now(timezone.utc).isoformat(),
        "deployer": deployer.address,
        "contracts": deployed,
    }

    DEPLOYMENTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = DEPLOYMENTS_DIR / "local.json"
    with out_path.open("w") as f:
        json.dump(output, f, indent=2)
    print(f"  ✓ Deployment record written → {out_path}")
    return deployed


# ---------------------------------------------------------------------------
# Phase 2: seed database
# ---------------------------------------------------------------------------

async def run_phase2_db(deployed: dict) -> None:
    print("\n[Phase 2] Seeding PostgreSQL …")
    dsn = _build_dsn()
    try:
        conn: asyncpg.Connection = await asyncpg.connect(dsn)
    except Exception as exc:
        print(f"  ✗ Cannot connect to PostgreSQL: {exc}", file=sys.stderr)
        print("    Is 'make up' running?", file=sys.stderr)
        sys.exit(1)

    try:
        # Lightweight bootstrap table — real schema is owned by Discovery migrations.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS seed_metadata (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                seeded_at  TIMESTAMPTZ DEFAULT now()
            )
        """)

        rows = [("seed.version", "1")]
        for name, info in deployed.items():
            rows.append((f"contract.{name}.address", info["address"]))
            rows.append((f"contract.{name}.deployedBlock", str(info["deployedBlock"])))

        await conn.executemany("""
            INSERT INTO seed_metadata (key, value)
            VALUES ($1, $2)
            ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, seeded_at = now()
        """, rows)

        print(f"  ✓ {len(rows)} rows written to seed_metadata")
    finally:
        await conn.close()


# ---------------------------------------------------------------------------
# Phase 3: verify Discovery health
# ---------------------------------------------------------------------------

async def run_phase3_services() -> None:
    print("\n[Phase 3] Checking Discovery Service …")
    headers = {"X-Admin-Key": ADMIN_API_KEY}
    async with httpx.AsyncClient(base_url=DISCOVERY_URL, headers=headers, timeout=10.0) as client:
        for attempt in range(15):
            try:
                resp = await client.get("/health/live")
                if resp.status_code == 200:
                    try:
                        body = resp.json()
                    except Exception:
                        body = resp.text
                    print(f"  ✓ Discovery healthy — {body}")
                    print("  ℹ  Sentinel enrollment will be available in TASK-021+.")
                    return
            except httpx.ConnectError:
                pass
            await asyncio.sleep(3)
        print("  ⚠  Discovery not reachable within timeout.", file=sys.stderr)
        print("    Run 'python scripts/seed.py' again once services are healthy.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _main() -> None:
    parser = argparse.ArgumentParser(description="Seed local dev environment")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--chain-only", action="store_true", help="Phase 1 only")
    group.add_argument("--db-only", action="store_true", help="Phases 2+3 only (needs existing local.json)")
    group.add_argument("--skip-chain", action="store_true", help="Phases 2+3 using existing local.json")
    args = parser.parse_args()

    deployed: dict = {}

    run_chain = not args.db_only
    run_db = not args.chain_only

    if run_chain and not args.skip_chain:
        deployed = run_phase1_chain()
    elif run_db:
        local_json = DEPLOYMENTS_DIR / "local.json"
        if local_json.exists():
            with local_json.open() as f:
                deployed = json.load(f).get("contracts", {})
            print(f"  ℹ Using existing deployment: {local_json}")
        elif args.skip_chain or args.db_only:
            print("  ✗ --skip-chain / --db-only requested but contracts/deployments/local.json not found.", file=sys.stderr)
            sys.exit(1)

    if run_db:
        await run_phase2_db(deployed)
        await run_phase3_services()

    print("\n✓ Seed complete.")


if __name__ == "__main__":
    asyncio.run(_main())


if __name__ == "__main__":
    asyncio.run(main())
