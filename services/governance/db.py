"""SQLite database layer for the Governance Admin app.

Tables:
  governance_key    — single row: the app's Ethereum keypair (created once)
  audit_log         — every action attempted (success or error), with TX hash
  registered_issuers  — issuers registered via this app
  trust_policies      — trust policies created via this app
  registered_services — services registered via this app
"""
import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("GOVERNANCE_DB_PATH", "/data/governance.db")


def get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS governance_key (
                id              INTEGER PRIMARY KEY,
                address         TEXT NOT NULL,
                private_key_hex TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at  TEXT NOT NULL,
                action      TEXT NOT NULL,
                entity_type TEXT,
                entity_id   TEXT,
                details     TEXT,
                tx_hash     TEXT,
                status      TEXT NOT NULL DEFAULT 'success',
                error_msg   TEXT
            );

            CREATE TABLE IF NOT EXISTS registered_issuers (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                did             TEXT NOT NULL UNIQUE,
                name            TEXT NOT NULL,
                description     TEXT,
                metadata_uri    TEXT,
                tx_hash         TEXT,
                registered_at   TEXT NOT NULL,
                is_active       INTEGER NOT NULL DEFAULT 1,
                revoked_at      TEXT,
                revoke_tx_hash  TEXT
            );

            CREATE TABLE IF NOT EXISTS trust_policies (
                id                          INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id                  TEXT NOT NULL UNIQUE,
                allowed_issuer_dids         TEXT NOT NULL,
                required_credential_types   TEXT NOT NULL,
                description                 TEXT,
                tx_hash                     TEXT,
                created_at                  TEXT NOT NULL,
                is_active                   INTEGER NOT NULL DEFAULT 1,
                deactivated_at              TEXT,
                deactivate_tx_hash          TEXT
            );

            CREATE TABLE IF NOT EXISTS registered_services (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id          TEXT NOT NULL UNIQUE,
                did                 TEXT NOT NULL,
                base_url            TEXT,
                role                TEXT NOT NULL,
                description         TEXT,
                tx_hash             TEXT,
                registered_at       TEXT NOT NULL,
                is_active           INTEGER NOT NULL DEFAULT 1,
                deregistered_at     TEXT,
                deregister_tx_hash  TEXT
            );
        """)

        # Generate governance keypair on first run
        row = conn.execute("SELECT id FROM governance_key WHERE id = 1").fetchone()
        if not row:
            from eth_account import Account  # noqa: PLC0415

            acct = Account.create()
            conn.execute(
                "INSERT INTO governance_key (id, address, private_key_hex, created_at) VALUES (1, ?, ?, ?)",
                (acct.address, acct.key.hex(), _now()),
            )
            conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_governance_key() -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM governance_key WHERE id = 1").fetchone()
        return dict(row) if row else None


def log_action(
    action: str,
    entity_type: str | None = None,
    entity_id: str | None = None,
    details: dict | None = None,
    tx_hash: str | None = None,
    status: str = "success",
    error_msg: str | None = None,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO audit_log
               (created_at, action, entity_type, entity_id, details, tx_hash, status, error_msg)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _now(),
                action,
                entity_type,
                entity_id,
                json.dumps(details) if details else None,
                tx_hash,
                status,
                error_msg,
            ),
        )
        conn.commit()


# ── Issuer helpers ──────────────────────────────────────────────────────────

def upsert_issuer(did: str, name: str, description: str, metadata_uri: str, tx_hash: str) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO registered_issuers (did, name, description, metadata_uri, tx_hash, registered_at, is_active)
               VALUES (?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(did) DO UPDATE SET
                   name=excluded.name, description=excluded.description,
                   metadata_uri=excluded.metadata_uri, tx_hash=excluded.tx_hash,
                   registered_at=excluded.registered_at, is_active=1,
                   revoked_at=NULL, revoke_tx_hash=NULL""",
            (did, name, description, metadata_uri, tx_hash, _now()),
        )
        conn.commit()


def mark_issuer_revoked(did: str, tx_hash: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE registered_issuers SET is_active=0, revoked_at=?, revoke_tx_hash=? WHERE did=?",
            (_now(), tx_hash, did),
        )
        conn.commit()


def get_all_issuers() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM registered_issuers ORDER BY registered_at DESC").fetchall()
        return [dict(r) for r in rows]


# ── Policy helpers ──────────────────────────────────────────────────────────

def upsert_policy(
    service_id: str,
    allowed_dids: list,
    cred_types: list,
    description: str,
    tx_hash: str,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO trust_policies
               (service_id, allowed_issuer_dids, required_credential_types, description, tx_hash, created_at, is_active)
               VALUES (?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(service_id) DO UPDATE SET
                   allowed_issuer_dids=excluded.allowed_issuer_dids,
                   required_credential_types=excluded.required_credential_types,
                   description=excluded.description,
                   tx_hash=excluded.tx_hash,
                   is_active=1,
                   deactivated_at=NULL, deactivate_tx_hash=NULL""",
            (service_id, json.dumps(allowed_dids), json.dumps(cred_types), description, tx_hash, _now()),
        )
        conn.commit()


def mark_policy_deactivated(service_id: str, tx_hash: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE trust_policies SET is_active=0, deactivated_at=?, deactivate_tx_hash=? WHERE service_id=?",
            (_now(), tx_hash, service_id),
        )
        conn.commit()


def get_all_policies() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM trust_policies ORDER BY created_at DESC").fetchall()
        result = []
        for r in rows:
            p = dict(r)
            p["allowed_issuer_dids"] = json.loads(p["allowed_issuer_dids"])
            p["required_credential_types"] = json.loads(p["required_credential_types"])
            result.append(p)
        return result


# ── Service helpers ─────────────────────────────────────────────────────────

def upsert_service(
    service_id: str,
    did: str,
    base_url: str,
    role: str,
    description: str,
    tx_hash: str,
) -> None:
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO registered_services
               (service_id, did, base_url, role, description, tx_hash, registered_at, is_active)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(service_id) DO UPDATE SET
                   did=excluded.did, base_url=excluded.base_url, role=excluded.role,
                   description=excluded.description, tx_hash=excluded.tx_hash,
                   registered_at=excluded.registered_at, is_active=1,
                   deregistered_at=NULL, deregister_tx_hash=NULL""",
            (service_id, did, base_url, role, description, tx_hash, _now()),
        )
        conn.commit()


def mark_service_deregistered(service_id: str, tx_hash: str) -> None:
    with get_conn() as conn:
        conn.execute(
            "UPDATE registered_services SET is_active=0, deregistered_at=?, deregister_tx_hash=? WHERE service_id=?",
            (_now(), tx_hash, service_id),
        )
        conn.commit()


def get_all_services() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM registered_services ORDER BY registered_at DESC").fetchall()
        return [dict(r) for r in rows]


# ── Audit helpers ────────────────────────────────────────────────────────────

def get_audit_log(limit: int = 500) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_stats() -> dict:
    with get_conn() as conn:
        return {
            "issuers": conn.execute("SELECT COUNT(*) FROM registered_issuers WHERE is_active=1").fetchone()[0],
            "policies": conn.execute("SELECT COUNT(*) FROM trust_policies WHERE is_active=1").fetchone()[0],
            "services": conn.execute("SELECT COUNT(*) FROM registered_services WHERE is_active=1").fetchone()[0],
            "audit": conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
        }
