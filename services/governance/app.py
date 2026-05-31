"""Governance Admin — FastAPI application.

Provides a simple browser UI for all governance contract operations:
  /              — Dashboard: key info, contract status, stats
  /bootstrap     — One-time role grant using deployer key
  /issuers       — Register / revoke issuers (IssuerRegistry)
  /policies      — Create / update / deactivate trust policies (TrustPolicyRegistry)
  /services      — Register / deregister services (ServiceRegistry)
  /audit         — Full audit log of every action
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import db
import chain as chain_module

templates = Jinja2Templates(directory="templates")

# Module-level chain client, initialised in lifespan
_chain: chain_module.GovernanceChainClient | None = None


def _get_chain() -> chain_module.GovernanceChainClient:
    if _chain is None:
        raise RuntimeError("Chain client not initialised")
    return _chain


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    global _chain
    db.init_db()
    gov_key = db.get_governance_key()
    rpc_url = os.environ.get("BLOCKCHAIN_RPC_URL", "http://hardhat:8545")
    contract_addresses = {
        "IssuerRegistry": os.environ.get("CONTRACT_ISSUER_REGISTRY", ""),
        "TrustPolicyRegistry": os.environ.get("CONTRACT_TRUST_POLICY_REGISTRY", ""),
        "StatusRegistry": os.environ.get("CONTRACT_STATUS_REGISTRY", ""),
        "ServiceRegistry": os.environ.get("CONTRACT_SERVICE_REGISTRY", ""),
    }
    if gov_key:
        _chain = chain_module.GovernanceChainClient(
            rpc_url=rpc_url,
            contract_addresses=contract_addresses,
            private_key=gov_key["private_key_hex"],
        )
    yield


app = FastAPI(title="Governance Admin", lifespan=lifespan)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _redirect(path: str, success: str = "", error: str = "") -> RedirectResponse:
    if success:
        return RedirectResponse(f"{path}?success={success}", status_code=303)
    if error:
        return RedirectResponse(f"{path}?error={error}", status_code=303)
    return RedirectResponse(path, status_code=303)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    gov_key = db.get_governance_key()
    client = _get_chain()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "gov_key": gov_key,
        "contracts": client.get_contract_info(),
        "roles": client.check_roles(gov_key["address"]),
        "chain_ok": client.is_connected(),
        "stats": db.get_stats(),
        "recent_audit": db.get_audit_log(limit=5),
    })


# ── Bootstrap ─────────────────────────────────────────────────────────────────

@app.get("/bootstrap", response_class=HTMLResponse)
async def bootstrap_page(request: Request, success: str = "", error: str = ""):
    gov_key = db.get_governance_key()
    client = _get_chain()
    roles = client.check_roles(gov_key["address"])
    return templates.TemplateResponse("bootstrap.html", {
        "request": request,
        "gov_key": gov_key,
        "roles": roles,
        "success": success,
        "error": error,
    })


@app.post("/bootstrap")
async def bootstrap_submit(deployer_key: str = Form(...)):
    client = _get_chain()
    results = client.bootstrap_grant_roles(deployer_key)
    errors = [f"{r['role']}: {r['error']}" for r in results if r["error"]]
    for r in results:
        db.log_action(
            "grant_role",
            entity_type="governance",
            entity_id=client.address,
            details={"role": r["role"]},
            tx_hash=r["tx_hash"],
            status="error" if r["error"] else "success",
            error_msg=r["error"],
        )
    if errors:
        return _redirect("/bootstrap", error="; ".join(errors))
    return _redirect("/bootstrap", success="All roles granted successfully")


# ── Issuers ───────────────────────────────────────────────────────────────────

@app.get("/issuers", response_class=HTMLResponse)
async def issuers_page(request: Request, success: str = "", error: str = ""):
    return templates.TemplateResponse("issuers.html", {
        "request": request,
        "issuers": db.get_all_issuers(),
        "success": success,
        "error": error,
    })


@app.post("/issuers/register")
async def register_issuer(
    did: str = Form(...),
    name: str = Form(...),
    description: str = Form(""),
    metadata_uri: str = Form(""),
):
    client = _get_chain()
    try:
        tx = client.register_issuer(did, name, description, metadata_uri)
        db.upsert_issuer(did, name, description, metadata_uri, tx)
        db.log_action("register_issuer", "issuer", did, {"name": name, "description": description}, tx_hash=tx)
        return _redirect("/issuers", success=f"Issuer '{name}' registered")
    except Exception as exc:
        db.log_action("register_issuer", "issuer", did, {"name": name}, status="error", error_msg=str(exc))
        return _redirect("/issuers", error=str(exc))


@app.post("/issuers/revoke")
async def revoke_issuer(did: str = Form(...)):
    client = _get_chain()
    try:
        tx = client.revoke_issuer(did)
        db.mark_issuer_revoked(did, tx)
        db.log_action("revoke_issuer", "issuer", did, {}, tx_hash=tx)
        return _redirect("/issuers", success="Issuer revoked")
    except Exception as exc:
        db.log_action("revoke_issuer", "issuer", did, {}, status="error", error_msg=str(exc))
        return _redirect("/issuers", error=str(exc))


@app.post("/issuers/update")
async def update_issuer(
    did: str = Form(...),
    name: str = Form(...),
    description: str = Form(""),
    metadata_uri: str = Form(""),
):
    client = _get_chain()
    try:
        tx = client.update_issuer(did, name, description, metadata_uri)
        db.upsert_issuer(did, name, description, metadata_uri, tx)
        db.log_action("update_issuer", "issuer", did, {"name": name}, tx_hash=tx)
        return _redirect("/issuers", success=f"Issuer '{name}' updated")
    except Exception as exc:
        db.log_action("update_issuer", "issuer", did, {"name": name}, status="error", error_msg=str(exc))
        return _redirect("/issuers", error=str(exc))


# ── Trust Policies ────────────────────────────────────────────────────────────

@app.get("/policies", response_class=HTMLResponse)
async def policies_page(request: Request, success: str = "", error: str = ""):
    return templates.TemplateResponse("policies.html", {
        "request": request,
        "policies": db.get_all_policies(),
        "success": success,
        "error": error,
    })


@app.post("/policies/create")
async def create_policy(
    service_id: str = Form(...),
    allowed_issuer_dids: str = Form(...),
    required_credential_types: str = Form(""),
    description: str = Form(""),
):
    client = _get_chain()
    dids = [d.strip() for d in allowed_issuer_dids.splitlines() if d.strip()]
    types = [t.strip() for t in required_credential_types.splitlines() if t.strip()]
    try:
        tx = client.create_policy(service_id, dids, types, description)
        db.upsert_policy(service_id, dids, types, description, tx)
        db.log_action("create_policy", "policy", service_id, {"allowed_dids": dids, "types": types}, tx_hash=tx)
        return _redirect("/policies", success=f"Policy for '{service_id}' created")
    except Exception as exc:
        db.log_action("create_policy", "policy", service_id, {}, status="error", error_msg=str(exc))
        return _redirect("/policies", error=str(exc))


@app.post("/policies/update")
async def update_policy(
    service_id: str = Form(...),
    allowed_issuer_dids: str = Form(...),
    required_credential_types: str = Form(""),
    description: str = Form(""),
):
    client = _get_chain()
    dids = [d.strip() for d in allowed_issuer_dids.splitlines() if d.strip()]
    types = [t.strip() for t in required_credential_types.splitlines() if t.strip()]
    try:
        tx = client.update_policy(service_id, dids, types, description)
        db.upsert_policy(service_id, dids, types, description, tx)
        db.log_action("update_policy", "policy", service_id, {"allowed_dids": dids, "types": types}, tx_hash=tx)
        return _redirect("/policies", success=f"Policy for '{service_id}' updated")
    except Exception as exc:
        db.log_action("update_policy", "policy", service_id, {}, status="error", error_msg=str(exc))
        return _redirect("/policies", error=str(exc))


@app.post("/policies/deactivate")
async def deactivate_policy(service_id: str = Form(...)):
    client = _get_chain()
    try:
        tx = client.deactivate_policy(service_id)
        db.mark_policy_deactivated(service_id, tx)
        db.log_action("deactivate_policy", "policy", service_id, {}, tx_hash=tx)
        return _redirect("/policies", success=f"Policy for '{service_id}' deactivated")
    except Exception as exc:
        db.log_action("deactivate_policy", "policy", service_id, {}, status="error", error_msg=str(exc))
        return _redirect("/policies", error=str(exc))


# ── Services ──────────────────────────────────────────────────────────────────

@app.get("/services", response_class=HTMLResponse)
async def services_page(request: Request, success: str = "", error: str = ""):
    return templates.TemplateResponse("services.html", {
        "request": request,
        "services": db.get_all_services(),
        "success": success,
        "error": error,
    })


@app.post("/services/register")
async def register_service(
    service_id: str = Form(...),
    did: str = Form(...),
    base_url: str = Form(""),
    role: str = Form("producer"),
    description: str = Form(""),
):
    client = _get_chain()
    try:
        tx = client.register_service(service_id, did, base_url, role, description)
        db.upsert_service(service_id, did, base_url, role, description, tx)
        db.log_action(
            "register_service", "service", service_id,
            {"did": did, "base_url": base_url, "role": role}, tx_hash=tx,
        )
        return _redirect("/services", success=f"Service '{service_id}' registered")
    except Exception as exc:
        db.log_action("register_service", "service", service_id, {}, status="error", error_msg=str(exc))
        return _redirect("/services", error=str(exc))


@app.post("/services/deregister")
async def deregister_service(service_id: str = Form(...)):
    client = _get_chain()
    try:
        tx = client.deregister_service(service_id)
        db.mark_service_deregistered(service_id, tx)
        db.log_action("deregister_service", "service", service_id, {}, tx_hash=tx)
        return _redirect("/services", success=f"Service '{service_id}' deregistered")
    except Exception as exc:
        db.log_action("deregister_service", "service", service_id, {}, status="error", error_msg=str(exc))
        return _redirect("/services", error=str(exc))


# ── Audit Log ─────────────────────────────────────────────────────────────────

@app.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    return templates.TemplateResponse("audit.html", {
        "request": request,
        "entries": db.get_audit_log(limit=500),
    })
