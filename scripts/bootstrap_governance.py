import os, sys
sys.path.insert(0, '/app')
os.chdir('/app')
import db as db_mod, chain as chain_mod

rpc = "http://hardhat:8545"
dk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

db_mod.init_db()
gov = db_mod.get_governance_key()
print("governance address:", gov["address"])

c = {
    "IssuerRegistry": os.environ.get("CONTRACT_ISSUER_REGISTRY", ""),
    "TrustPolicyRegistry": os.environ.get("CONTRACT_TRUST_POLICY_REGISTRY", ""),
    "StatusRegistry": os.environ.get("CONTRACT_STATUS_REGISTRY", ""),
    "ServiceRegistry": os.environ.get("CONTRACT_SERVICE_REGISTRY", ""),
}
print("contracts:", c)

cl = chain_mod.GovernanceChainClient(rpc, c, gov["private_key_hex"])
for r in cl.bootstrap_grant_roles(dk):
    print("[OK]" if not r["error"] else "[FAIL]", r["role"], r["tx_hash"], r["error"])
