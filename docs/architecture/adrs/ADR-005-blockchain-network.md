# ADR-005 — Blockchain Network Selection

**Status:** ACCEPTED  
**Date:** 2025-01-01  
**Deciders:** Platform Architecture Working Group

---

## Context

The platform uses a blockchain as an immutable trust anchor for:
- Sentinel DID registration (`SentinelRegistry`)
- Issuer lifecycle management (`IssuerRegistry`)
- Trust policy parameters, e.g. Δ (`TrustPolicyRegistry`)
- Status list hash anchoring (`StatusListAnchor`)

Requirements:
1. **EVM compatibility** — the smart contract language is Solidity; existing
   tooling (Hardhat, OpenZeppelin) targets the EVM.
2. **Permissioned access** — only authorized entities should be able to
   register Sentinels or modify issuer status.
3. **Low gas cost** — frequent writes (status list updates, Sentinel join
   events) must be inexpensive.
4. **Production-grade** — the network must have SLA guarantees suitable for
   government deployments.
5. **Local development** — engineers must be able to run a local chain for
   testing without token/gas acquisition.

---

## Decision

**Primary network: Ethereum Sepolia testnet** (development / integration testing)  
**Local development: Hardhat local node** (chainId 31337)  
**Production: permissioned EVM chain** (Hyperledger Besu, private network, or
a government-operated L2 — final selection deferred to production deployment)

### Rationale for Sepolia (not Mainnet) in testing

Sepolia is the official Ethereum testnet.  Faucet ETH is freely available.
Sepolia's chain ID (11155111) differs from mainnet (1), preventing accidental
mainnet interactions.

### Smart Contract Access Control

All write operations on `SentinelRegistry` and `IssuerRegistry` are gated
behind an `AccessControl` role pattern (OpenZeppelin 5.0 `AccessControl`).
The `ADMIN_ROLE` is held by a multi-sig wallet (production) or the deployer
EOA (testnet).

---

## Consequences

### Positive

- **EVM tooling** — Hardhat, Foundry, Ethers.js, Web3.py, OpenZeppelin are
  all production-grade and well-maintained.
- **Audit trail** — every on-chain state change is immutable and publicly
  verifiable (on public testnets) or verifiable by all consortium members
  (on a permissioned chain).
- **Local dev** — `npx hardhat node` provides a fully functional local chain
  with block mining, time manipulation, and snapshot support.
- **OpenZeppelin 5.0** — provides audited `AccessControl`, `Ownable2Step`,
  and upgrade patterns.

### Negative

- **Block time latency** — writing to chain takes ≥ 1 block (Sepolia: ~12 s).
  All reads use local cache; on-chain writes are asynchronous relative to the
  request flow.
- **RPC dependency** — a live RPC endpoint is required for Sentinel on-chain
  reads.  Mitigated by: (a) local caching with TTL, and (b) node fallback
  list in config.
- **Production chain TBD** — the final production network is not yet selected.
  The codebase is parameterised via `BLOCKCHAIN_RPC_URL` and contract addresses
  in environment config.

---

## Rejected Alternatives

### Ethereum Mainnet (immediate)

Real ETH cost for every registration and update.  Not acceptable for a
government platform where frequent administrative operations would accrue
meaningful cost.

### Hyperledger Fabric

Not EVM-compatible; requires a completely different smart-contract language
(Go chaincode).  Incompatible with existing Hardhat / OpenZeppelin tooling.

### Cardano / Solana / other L1

Non-EVM.  Different programming models; limited enterprise tooling; smaller
developer ecosystem in the target region.

### No blockchain (centralized registry only)

Eliminates the immutable trust anchor.  Discovery becomes a single point of
trust — a compromised Discovery can silently modify the issuer registry.
Violates the zero-trust architecture requirement.

---

## References

- Ethereum Sepolia testnet — https://sepolia.etherscan.io/
- Hardhat — https://hardhat.org/
- OpenZeppelin Contracts v5 — https://docs.openzeppelin.com/contracts/5.x/
- Hyperledger Besu (permissioned EVM) — https://besu.hyperledger.org/
