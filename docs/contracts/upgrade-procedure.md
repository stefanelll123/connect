# Registry Contracts — Upgrade Procedure

This runbook covers deploying a new implementation version and executing the upgrade via TimelockController.

---

## Overview

| Component | Pattern |
|-----------|---------|
| Proxy type | TransparentUpgradeableProxy (OZ v5) |
| Implementation base | `Initializable` + `AccessControlUpgradeable` |
| Governance | `TimelockController` (min 48h on mainnet, 5m on testnet) |
| ProxyAdmin owner | `TimelockController` — never an EOA |
| Storage safety | `__gap[50]` reserved in every implementation |

---

## Section 1 — Pre-Upgrade Checklist

Before deploying a new implementation:

1. **Validate storage layout compatibility:**
   ```bash
   npx hardhat run scripts/upgrade/verify-storage-layout.ts --network <network>
   ```
   This runs `upgrades.validateUpgrade()` against the current proxy and new factory. The command **must** pass with zero errors before proceeding.

2. **Check contract size** (EIP-170 limit: 24 576 bytes):
   ```bash
   npx hardhat size-contracts
   ```
   All contracts must be `< 24 KB`.

3. **Run the full test suite** against the new implementation:
   ```bash
   npx hardhat test
   npx hardhat coverage
   ```
   Coverage must be ≥ 95% branch coverage.

4. **Run Slither static analysis:**
   ```bash
   slither contracts/ --filter-paths '@openzeppelin' --checklist > slither-report.md
   ```
   Zero HIGH severity findings. Any MEDIUM finding must be documented in `.slither.config.json`.

5. Confirm the `__gap[50]` array remains last in the contract storage layout.

---

## Section 2 — Deploy New Implementation

The upgrade script automatically deploys the new implementation without touching the proxy:

```bash
UPGRADE_CONTRACT=IssuerRegistry \
PROXY_ADDRESS=<proxy-address-from-deployments/proxies.json> \
TIMELOCK_ADDRESS=<timelock-address> \
DEPLOYER_PRIVATE_KEY=<proposer-key> \
npx hardhat run scripts/upgrade/upgrade-v2.ts --network <network>
```

This will:
- Compile and deploy the new implementation contract
- Encode the `ProxyAdmin.upgradeAndCall()` calldata
- Call `TimelockController.schedule()` with the appropriate delay
- Save the upgrade record to `deployments/upgrades.json`

**Note:** The proxy is NOT upgraded yet — only scheduled.

---

## Section 3 — Propose Upgrade to Timelock

The schedule call from Section 2 creates a pending timelock operation. Record the `salt` printed by the script — it is required in Section 5 to execute.

Confirm the proposal was accepted:
```bash
# Check operation is pending
cast call <timelock-address> "isOperationPending(bytes32)(bool)" <operationId>
```

---

## Section 4 — Wait for Delay

| Network | Minimum Delay |
|---------|---------------|
| Mainnet | 172 800 s (48 hours) |
| Sepolia testnet | 300 s (5 minutes) |
| Hardhat local | 300 s (5 minutes) |

The operation cannot be executed before the delay expires. Plan upgrade windows accordingly.

---

## Section 5 — Execute Upgrade

After the delay has elapsed, **anyone** can execute the scheduled operation (executors is `address(0)`):

```bash
cast send <timelock-address> \
  "execute(address,uint256,bytes,bytes32,bytes32)" \
  <proxyAdmin-address> 0 <encoded-calldata> <predecessor> <salt> \
  --private-key <any-funded-key> \
  --rpc-url <rpc-url>
```

Or use the upgrade script with `--execute` flag (extend `upgrade-v2.ts` for automated execution).

Verify the upgrade:
```bash
cast call <proxy-address> "implementation()(address)"
# Should return the new implementation address
```

---

## Section 6 — Post-Upgrade Smoke Test

1. Confirm all role assignments are intact:
   ```bash
   cast call <proxy> "hasRole(bytes32,address)(bool)" \
     "$(cast keccak 'ISSUER_ADMIN_ROLE')" <admin-address>
   ```

2. Confirm existing data survived (no storage layout corruption):
   ```bash
   cast call <issuer-proxy> "getIssuerCount()(uint256)"
   ```

3. Confirm `initialize()` cannot be called again:
   ```bash
   cast call <proxy> "initialize(address)" <any-address>
   # Must revert with InvalidInitialization
   ```

4. Run contract integration tests against the mainnet fork:
   ```bash
   FORK_URL=<mainnet-rpc> npx hardhat test --network hardhat
   ```

---

## Storage Layout Rules

When writing V2+ implementations:

1. **NEVER** reorder, rename, or remove existing storage variables.
2. **NEVER** change the type of an existing variable.
3. **ALWAYS** append new variables after existing ones (before `__gap`).
4. **Reduce `__gap` size** by the number of new slots added.  
   Example: adding one `uint256` reduces `__gap[50]` → `__gap[49]`.
5. **Document** every storage change in the `@custom:storage-layout` NatSpec block.

---

## Emergency Rollback

If a critical bug is found immediately after an upgrade, re-propose the previous implementation address through the Timelock as a new upgrade. There is no instant rollback — the Timelock delay applies to all upgrades, including rollbacks. Plan accordingly.
