"""Web3 chain client for the Governance Admin app.

Uses hardcoded minimal ABIs — no external ABI files required.
Supports all governance write operations across the 4 registries.
"""
from __future__ import annotations

from eth_account import Account
from web3 import Web3

# ── Known custom error selectors (4-byte keccak prefixes) ───────────────────
_CONTRACT_ERRORS: dict[str, str] = {
    "0x7aa81aa7": "DID is already registered on chain (IssuerAlreadyRegistered)",
    "0xcd1b84ce": "DID not found on chain (IssuerNotFound)",
    "0xc55b7c1b": "DID is already revoked (IssuerAlreadyRevoked)",
    "0xc10cc588": "DID length is invalid — must be 1-2048 bytes (InvalidDID)",
    "0xcfedcfd8": "Policy already exists for this service (PolicyAlreadyExists)",
    "0xf90d6e6b": "Policy not found for this service (PolicyNotFound)",
    "0xed03135f": "Service is already registered (ServiceAlreadyRegistered)",
    "0x97c1c13b": "Service not found (ServiceNotFound)",
}


def _decode_contract_error(exc: Exception) -> str:
    """Return a readable message for known contract custom errors, or str(exc)."""
    s = str(exc)
    for selector, msg in _CONTRACT_ERRORS.items():
        if selector in s.lower():
            return msg
    return s

# ── Minimal ABIs ────────────────────────────────────────────────────────────

ISSUER_REGISTRY_ABI: list[dict] = [
    {
        "inputs": [{"name": "didHash", "type": "bytes32"}],
        "name": "IssuerAlreadyRegistered",
        "type": "error",
    },
    {
        "inputs": [{"name": "didHash", "type": "bytes32"}],
        "name": "IssuerNotFound",
        "type": "error",
    },
    {
        "inputs": [{"name": "reason", "type": "string"}],
        "name": "InvalidDID",
        "type": "error",
    },
    {
        "inputs": [
            {"name": "did", "type": "string"},
            {"name": "name", "type": "string"},
            {"name": "description", "type": "string"},
            {"name": "metadataURI", "type": "string"},
        ],
        "name": "registerIssuer",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "did", "type": "string"}],
        "name": "revokeIssuer",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "did", "type": "string"},
            {"name": "name", "type": "string"},
            {"name": "description", "type": "string"},
            {"name": "metadataURI", "type": "string"},
        ],
        "name": "updateIssuer",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "did", "type": "string"}],
        "name": "isIssuerActive",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "did", "type": "string"}],
        "name": "getIssuer",
        "outputs": [
            {
                "components": [
                    {"name": "did", "type": "string"},
                    {"name": "name", "type": "string"},
                    {"name": "description", "type": "string"},
                    {"name": "registeredAt", "type": "uint256"},
                    {"name": "updatedAt", "type": "uint256"},
                    {"name": "active", "type": "bool"},
                    {"name": "metadataURI", "type": "string"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "getIssuerCount",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "index", "type": "uint256"}],
        "name": "getIssuerAtIndex",
        "outputs": [
            {
                "components": [
                    {"name": "did", "type": "string"},
                    {"name": "name", "type": "string"},
                    {"name": "description", "type": "string"},
                    {"name": "registeredAt", "type": "uint256"},
                    {"name": "updatedAt", "type": "uint256"},
                    {"name": "active", "type": "bool"},
                    {"name": "metadataURI", "type": "string"},
                ],
                "name": "",
                "type": "tuple",
            }
        ],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "ISSUER_ADMIN_ROLE",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "DEFAULT_ADMIN_ROLE",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "role", "type": "bytes32"}, {"name": "account", "type": "address"}],
        "name": "grantRole",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "role", "type": "bytes32"}, {"name": "account", "type": "address"}],
        "name": "hasRole",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "didHash", "type": "bytes32"},
            {"indexed": False, "name": "did", "type": "string"},
            {"indexed": False, "name": "name", "type": "string"},
            {"indexed": True, "name": "registeredBy", "type": "address"},
        ],
        "name": "IssuerRegistered",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "didHash", "type": "bytes32"},
            {"indexed": False, "name": "did", "type": "string"},
            {"indexed": True, "name": "revokedBy", "type": "address"},
        ],
        "name": "IssuerRevoked",
        "type": "event",
    },
]

TRUST_POLICY_REGISTRY_ABI: list[dict] = [
    {
        "inputs": [
            {"name": "serviceId", "type": "string"},
            {"name": "allowedIssuerDids", "type": "string[]"},
            {"name": "requiredCredentialTypes", "type": "string[]"},
            {"name": "description", "type": "string"},
        ],
        "name": "createPolicy",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "serviceId", "type": "string"},
            {"name": "allowedIssuerDids", "type": "string[]"},
            {"name": "requiredCredentialTypes", "type": "string[]"},
            {"name": "description", "type": "string"},
        ],
        "name": "updatePolicy",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "serviceId", "type": "string"}],
        "name": "deactivatePolicy",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "serviceId", "type": "string"}],
        "name": "isPolicyActive",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "POLICY_ADMIN_ROLE",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "DEFAULT_ADMIN_ROLE",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "role", "type": "bytes32"}, {"name": "account", "type": "address"}],
        "name": "grantRole",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "role", "type": "bytes32"}, {"name": "account", "type": "address"}],
        "name": "hasRole",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "serviceIdHash", "type": "bytes32"},
            {"indexed": False, "name": "serviceId", "type": "string"},
            {"indexed": False, "name": "version", "type": "uint256"},
            {"indexed": True, "name": "createdBy", "type": "address"},
        ],
        "name": "PolicyCreated",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "serviceIdHash", "type": "bytes32"},
            {"indexed": False, "name": "serviceId", "type": "string"},
            {"indexed": False, "name": "version", "type": "uint256"},
            {"indexed": True, "name": "updatedBy", "type": "address"},
        ],
        "name": "PolicyUpdated",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "serviceIdHash", "type": "bytes32"},
            {"indexed": False, "name": "serviceId", "type": "string"},
            {"indexed": True, "name": "deactivatedBy", "type": "address"},
        ],
        "name": "PolicyDeactivated",
        "type": "event",
    },
]

STATUS_REGISTRY_ABI: list[dict] = [
    {
        "inputs": [],
        "name": "ANCHOR_PUBLISHER_ROLE",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "REVOCATION_ADMIN_ROLE",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "DEFAULT_ADMIN_ROLE",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "role", "type": "bytes32"}, {"name": "account", "type": "address"}],
        "name": "grantRole",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "role", "type": "bytes32"}, {"name": "account", "type": "address"}],
        "name": "hasRole",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
]

SERVICE_REGISTRY_ABI: list[dict] = [
    {
        "inputs": [
            {"name": "serviceId", "type": "string"},
            {"name": "did", "type": "string"},
            {"name": "baseUrl", "type": "string"},
            {"name": "role", "type": "string"},
            {"name": "description", "type": "string"},
        ],
        "name": "registerService",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "serviceId", "type": "string"},
            {"name": "newBaseUrl", "type": "string"},
            {"name": "description", "type": "string"},
        ],
        "name": "updateService",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "serviceId", "type": "string"}],
        "name": "deregisterService",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "serviceId", "type": "string"}],
        "name": "isServiceActive",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "SERVICE_REGISTRY_ADMIN_ROLE",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [],
        "name": "DEFAULT_ADMIN_ROLE",
        "outputs": [{"name": "", "type": "bytes32"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [{"name": "role", "type": "bytes32"}, {"name": "account", "type": "address"}],
        "name": "grantRole",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "role", "type": "bytes32"}, {"name": "account", "type": "address"}],
        "name": "hasRole",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "serviceIdHash", "type": "bytes32"},
            {"indexed": False, "name": "serviceId", "type": "string"},
            {"indexed": False, "name": "did", "type": "string"},
            {"indexed": False, "name": "baseUrl", "type": "string"},
            {"indexed": False, "name": "role", "type": "string"},
            {"indexed": True, "name": "registeredBy", "type": "address"},
        ],
        "name": "ServiceRegistered",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "serviceIdHash", "type": "bytes32"},
            {"indexed": False, "name": "serviceId", "type": "string"},
            {"indexed": True, "name": "deregisteredBy", "type": "address"},
        ],
        "name": "ServiceDeregistered",
        "type": "event",
    },
]

_ABI_MAP = {
    "IssuerRegistry": ISSUER_REGISTRY_ABI,
    "TrustPolicyRegistry": TRUST_POLICY_REGISTRY_ABI,
    "StatusRegistry": STATUS_REGISTRY_ABI,
    "ServiceRegistry": SERVICE_REGISTRY_ABI,
}


# ── Client ───────────────────────────────────────────────────────────────────

class GovernanceChainClient:
    def __init__(self, rpc_url: str, contract_addresses: dict[str, str], private_key: str) -> None:
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self._account = Account.from_key(private_key)
        self.address = self._account.address
        self._contract_addresses = contract_addresses

        self._contracts: dict[str, object] = {}
        for name, addr in contract_addresses.items():
            if addr and name in _ABI_MAP:
                self._contracts[name] = self.w3.eth.contract(
                    address=Web3.to_checksum_address(addr),
                    abi=_ABI_MAP[name],
                )

    # ── Connectivity ──────────────────────────────────────────────────────

    def is_connected(self) -> bool:
        try:
            return self.w3.is_connected()
        except Exception:
            return False

    def get_contract_info(self) -> list[dict]:
        """Return deployment status for all 4 registries."""
        result = []
        for name in ("IssuerRegistry", "TrustPolicyRegistry", "StatusRegistry", "ServiceRegistry"):
            addr = self._contract_addresses.get(name, "")
            deployed = False
            if addr:
                try:
                    code = self.w3.eth.get_code(Web3.to_checksum_address(addr))
                    deployed = len(code) > 2
                except Exception:
                    pass
            result.append({"name": name, "address": addr, "deployed": deployed})
        return result

    # ── Role checks ───────────────────────────────────────────────────────

    def check_roles(self, address: str) -> dict[str, bool]:
        checks = {
            "ISSUER_ADMIN_ROLE": ("IssuerRegistry", "ISSUER_ADMIN_ROLE"),
            "POLICY_ADMIN_ROLE": ("TrustPolicyRegistry", "POLICY_ADMIN_ROLE"),
            "SERVICE_REGISTRY_ADMIN_ROLE": ("ServiceRegistry", "SERVICE_REGISTRY_ADMIN_ROLE"),
        }
        result: dict[str, bool] = {}
        for label, (contract_name, role_fn) in checks.items():
            try:
                c = self._contracts[contract_name]
                role_bytes = getattr(c.functions, role_fn)().call()
                result[label] = c.functions.hasRole(role_bytes, address).call()
            except Exception:
                result[label] = False
        return result

    # ── Internal TX helper ────────────────────────────────────────────────

    def _send_tx(self, fn) -> str:
        """Sign and send a transaction using the governance key. Returns tx_hash hex."""
        # Simulate first to get a readable revert reason before spending gas.
        try:
            fn.call({"from": self.address})
        except Exception as sim_exc:
            raise RuntimeError(_decode_contract_error(sim_exc)) from sim_exc
        nonce = self.w3.eth.get_transaction_count(self.address)
        tx = fn.build_transaction({
            "from": self.address,
            "nonce": nonce,
            "gas": 500_000,
            "gasPrice": self.w3.eth.gas_price,
            "chainId": self.w3.eth.chain_id,
        })
        signed = self.w3.eth.account.sign_transaction(tx, self._account.key)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        if receipt.status != 1:
            raise RuntimeError(f"Transaction reverted (tx={tx_hash.hex()})")
        return tx_hash.hex()

    def _send_tx_with_key(self, fn, private_key: str) -> str:
        """Sign with an external key (bootstrap grantRole). Key is never stored."""
        acct = Account.from_key(private_key)
        nonce = self.w3.eth.get_transaction_count(acct.address)
        tx = fn.build_transaction({
            "from": acct.address,
            "nonce": nonce,
            "gas": 200_000,
            "gasPrice": self.w3.eth.gas_price,
            "chainId": self.w3.eth.chain_id,
        })
        signed = self.w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        if receipt.status != 1:
            raise RuntimeError(f"Transaction reverted (tx={tx_hash.hex()})")
        return tx_hash.hex()

    # ── Bootstrap: grant roles to governance key ──────────────────────────

    def bootstrap_grant_roles(self, deployer_key: str) -> list[dict]:
        """Fund governance address with ETH for gas, then grant
        ISSUER_ADMIN_ROLE, POLICY_ADMIN_ROLE, SERVICE_REGISTRY_ADMIN_ROLE
        to this app's governance address using deployer_key.
        Returns list of {role, tx_hash, error}."""
        target = self.address
        results = []

        # Step 0: Fund governance address so it can pay gas
        try:
            deployer_acct = Account.from_key(deployer_key)
            current_balance = self.w3.eth.get_balance(target)
            if current_balance < self.w3.to_wei(0.1, "ether"):
                nonce = self.w3.eth.get_transaction_count(deployer_acct.address)
                fund_tx = {
                    "from": deployer_acct.address,
                    "to": target,
                    "value": self.w3.to_wei(1, "ether"),
                    "nonce": nonce,
                    "gas": 21_000,
                    "gasPrice": self.w3.eth.gas_price,
                    "chainId": self.w3.eth.chain_id,
                }
                signed = self.w3.eth.account.sign_transaction(fund_tx, deployer_key)
                tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
                self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
                results.append({"role": "fund_gas (1 ETH sent)", "tx_hash": tx_hash.hex(), "error": None})
            else:
                results.append({"role": "fund_gas (already funded)", "tx_hash": None, "error": None})
        except Exception as exc:
            results.append({"role": "fund_gas", "tx_hash": None, "error": str(exc)})

        # Steps 1–3: Grant roles
        grants = [
            ("ISSUER_ADMIN_ROLE", "IssuerRegistry", "ISSUER_ADMIN_ROLE"),
            ("POLICY_ADMIN_ROLE", "TrustPolicyRegistry", "POLICY_ADMIN_ROLE"),
            ("SERVICE_REGISTRY_ADMIN_ROLE", "ServiceRegistry", "SERVICE_REGISTRY_ADMIN_ROLE"),
        ]
        for label, contract_name, role_fn in grants:
            try:
                c = self._contracts[contract_name]
                role_bytes = getattr(c.functions, role_fn)().call()
                tx = self._send_tx_with_key(c.functions.grantRole(role_bytes, target), deployer_key)
                results.append({"role": label, "tx_hash": tx, "error": None})
            except Exception as exc:
                results.append({"role": label, "tx_hash": None, "error": str(exc)})
        return results

    # ── IssuerRegistry ────────────────────────────────────────────────────

    def register_issuer(self, did: str, name: str, description: str, metadata_uri: str = "") -> str:
        c = self._contracts["IssuerRegistry"]
        return self._send_tx(c.functions.registerIssuer(did, name, description, metadata_uri))

    def revoke_issuer(self, did: str) -> str:
        c = self._contracts["IssuerRegistry"]
        return self._send_tx(c.functions.revokeIssuer(did))

    def update_issuer(self, did: str, name: str, description: str, metadata_uri: str = "") -> str:
        c = self._contracts["IssuerRegistry"]
        return self._send_tx(c.functions.updateIssuer(did, name, description, metadata_uri))

    def is_issuer_active(self, did: str) -> bool:
        return self._contracts["IssuerRegistry"].functions.isIssuerActive(did).call()

    def get_chain_issuers(self) -> list[dict]:
        """Read all active issuers directly from the contract (for chain sync view)."""
        c = self._contracts["IssuerRegistry"]
        count: int = c.functions.getIssuerCount().call()
        results = []
        for i in range(count):
            r = c.functions.getIssuerAtIndex(i).call()
            results.append({
                "did": r[0], "name": r[1], "description": r[2],
                "registeredAt": r[3], "updatedAt": r[4],
                "active": r[5], "metadataURI": r[6],
            })
        return results

    # ── TrustPolicyRegistry ───────────────────────────────────────────────

    def create_policy(
        self, service_id: str, allowed_dids: list[str], cred_types: list[str], description: str
    ) -> str:
        c = self._contracts["TrustPolicyRegistry"]
        return self._send_tx(c.functions.createPolicy(service_id, allowed_dids, cred_types, description))

    def update_policy(
        self, service_id: str, allowed_dids: list[str], cred_types: list[str], description: str
    ) -> str:
        c = self._contracts["TrustPolicyRegistry"]
        return self._send_tx(c.functions.updatePolicy(service_id, allowed_dids, cred_types, description))

    def deactivate_policy(self, service_id: str) -> str:
        c = self._contracts["TrustPolicyRegistry"]
        return self._send_tx(c.functions.deactivatePolicy(service_id))

    def is_policy_active(self, service_id: str) -> bool:
        return self._contracts["TrustPolicyRegistry"].functions.isPolicyActive(service_id).call()

    # ── ServiceRegistry ───────────────────────────────────────────────────

    def register_service(
        self, service_id: str, did: str, base_url: str, role: str, description: str
    ) -> str:
        c = self._contracts["ServiceRegistry"]
        return self._send_tx(c.functions.registerService(service_id, did, base_url, role, description))

    def deregister_service(self, service_id: str) -> str:
        c = self._contracts["ServiceRegistry"]
        return self._send_tx(c.functions.deregisterService(service_id))

    def is_service_active(self, service_id: str) -> bool:
        return self._contracts["ServiceRegistry"].functions.isServiceActive(service_id).call()
