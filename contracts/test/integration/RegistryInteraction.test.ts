import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";
import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

/**
 * TASK-019 — Integration tests for cross-contract registry interactions.
 *
 * Tests scenarios spanning multiple registries:
 *  - TrustPolicyRegistry validates issuers against IssuerRegistry
 *  - Revoking an issuer affects subsequent policy validation
 *  - Initialize() cannot be called twice (upgradeable invariant)
 *  - Full lifecycle: register issuer → create policy → anchor status → list service
 */
describe("RegistryInteraction — integration (TASK-019)", function () {
  // -------------------------------------------------------------------------
  // Fixtures
  // -------------------------------------------------------------------------

  async function deployAllRegistriesFixture() {
    const [admin, user1, user2] = await ethers.getSigners();

    const IRFactory = await ethers.getContractFactory("IssuerRegistry");
    const issuerRegistry = await upgrades.deployProxy(IRFactory, [admin.address], {
      kind: "transparent",
    });

    const TPRFactory = await ethers.getContractFactory("TrustPolicyRegistry");
    const trustPolicyRegistry = await upgrades.deployProxy(
      TPRFactory,
      [admin.address, await issuerRegistry.getAddress()],
      { kind: "transparent" }
    );

    const SRFactory = await ethers.getContractFactory("StatusRegistry");
    const statusRegistry = await upgrades.deployProxy(
      SRFactory,
      [admin.address, await issuerRegistry.getAddress()],
      { kind: "transparent" }
    );

    const SvcFactory = await ethers.getContractFactory("ServiceRegistry");
    const serviceRegistry = await upgrades.deployProxy(SvcFactory, [admin.address], {
      kind: "transparent",
    });

    return { admin, user1, user2, issuerRegistry, trustPolicyRegistry, statusRegistry, serviceRegistry };
  }

  // -------------------------------------------------------------------------
  // Upgradeable invariants (TASK-018 acceptance criteria)
  // -------------------------------------------------------------------------

  describe("Upgradeable invariants", function () {
    it("IssuerRegistry initialize() reverts with InvalidInitialization on second call", async function () {
      const { admin, issuerRegistry } = await loadFixture(deployAllRegistriesFixture);
      await expect(
        issuerRegistry.initialize(admin.address)
      ).to.be.revertedWithCustomError(issuerRegistry, "InvalidInitialization");
    });

    it("TrustPolicyRegistry initialize() reverts on second call", async function () {
      const { admin, trustPolicyRegistry, issuerRegistry } =
        await loadFixture(deployAllRegistriesFixture);
      await expect(
        trustPolicyRegistry.initialize(admin.address, await issuerRegistry.getAddress())
      ).to.be.revertedWithCustomError(trustPolicyRegistry, "InvalidInitialization");
    });

    it("StatusRegistry initialize() reverts on second call", async function () {
      const { admin, statusRegistry, issuerRegistry } =
        await loadFixture(deployAllRegistriesFixture);
      await expect(
        statusRegistry.initialize(admin.address, await issuerRegistry.getAddress())
      ).to.be.revertedWithCustomError(statusRegistry, "InvalidInitialization");
    });

    it("ServiceRegistry initialize() reverts on second call", async function () {
      const { admin, serviceRegistry } = await loadFixture(deployAllRegistriesFixture);
      await expect(
        serviceRegistry.initialize(admin.address)
      ).to.be.revertedWithCustomError(serviceRegistry, "InvalidInitialization");
    });
  });

  // -------------------------------------------------------------------------
  // Cross-contract: IssuerRegistry ↔ TrustPolicyRegistry
  // -------------------------------------------------------------------------

  describe("IssuerRegistry → TrustPolicyRegistry cross-contract", function () {
    it("createPolicy succeeds only for active issuers", async function () {
      const { admin, issuerRegistry, trustPolicyRegistry } =
        await loadFixture(deployAllRegistriesFixture);

      await issuerRegistry.registerIssuer("did:key:issuerA", "Issuer A", "", "");
      await trustPolicyRegistry.createPolicy(
        "svc:integration:1",
        ["did:key:issuerA"],
        ["VerifiableCredential"],
        "test"
      );
      expect(await trustPolicyRegistry.isPolicyActive("svc:integration:1")).to.be.true;
    });

    it("createPolicy reverts when issuer not in IssuerRegistry", async function () {
      const { trustPolicyRegistry } = await loadFixture(deployAllRegistriesFixture);
      await expect(
        trustPolicyRegistry.createPolicy(
          "svc:integration:2",
          ["did:key:unknownIssuer"],
          [],
          "bad"
        )
      ).to.be.revertedWithCustomError(trustPolicyRegistry, "UnknownIssuer");
    });

    it("revoking issuer prevents new policy creation referencing that issuer", async function () {
      const { admin, issuerRegistry, trustPolicyRegistry } =
        await loadFixture(deployAllRegistriesFixture);

      await issuerRegistry.registerIssuer("did:key:issuerB", "Issuer B", "", "");
      await issuerRegistry.revokeIssuer("did:key:issuerB");

      await expect(
        trustPolicyRegistry.createPolicy("svc:integration:3", ["did:key:issuerB"], [], "")
      ).to.be.revertedWithCustomError(trustPolicyRegistry, "UnknownIssuer");
    });

    it("isIssuerAllowedForService reflects policy allowlist correctly", async function () {
      const { admin, issuerRegistry, trustPolicyRegistry } =
        await loadFixture(deployAllRegistriesFixture);

      await issuerRegistry.registerIssuer("did:key:allowed", "Allowed", "", "");
      await issuerRegistry.registerIssuer("did:key:other", "Other", "", "");

      await trustPolicyRegistry.createPolicy(
        "svc:integration:4",
        ["did:key:allowed"],
        [],
        "allowlist test"
      );

      expect(
        await trustPolicyRegistry.isIssuerAllowedForService("svc:integration:4", "did:key:allowed")
      ).to.be.true;
      expect(
        await trustPolicyRegistry.isIssuerAllowedForService("svc:integration:4", "did:key:other")
      ).to.be.false;
    });
  });

  // -------------------------------------------------------------------------
  // Full lifecycle
  // -------------------------------------------------------------------------

  describe("Full lifecycle across all four registries", function () {
    it("completes register → policy → anchor → service workflow", async function () {
      const { admin, issuerRegistry, trustPolicyRegistry, statusRegistry, serviceRegistry } =
        await loadFixture(deployAllRegistriesFixture);

      // 1. Register issuer
      await issuerRegistry.registerIssuer("did:key:gov", "Government CA", "root CA", "");
      expect(await issuerRegistry.isIssuerActive("did:key:gov")).to.be.true;

      // 2. Create trust policy
      await trustPolicyRegistry.createPolicy(
        "svc:passport:verify",
        ["did:key:gov"],
        ["PassportCredential"],
        "passport policy"
      );
      expect(await trustPolicyRegistry.isPolicyActive("svc:passport:verify")).to.be.true;

      // 3. Publish status anchor
      const credHash = ethers.keccak256(ethers.toUtf8Bytes("passport-status-list-jwt"));
      await statusRegistry.publishStatusAnchor(
        "did:key:gov",
        0n,
        credHash,
        "https://gov.example.com/status/0.json",
        3600n
      );
      expect(
        await statusRegistry.verifyStatusAnchor("did:key:gov", 0n, credHash)
      ).to.be.true;

      // 4. Register service endpoint
      await serviceRegistry.registerService(
        "svc:passport:verify",
        "did:key:gov",
        "http://localhost:8080",
        "producer",
        "passport verifier"
      );
      expect(await serviceRegistry.isServiceActive("svc:passport:verify")).to.be.true;
    });
  });

  // -------------------------------------------------------------------------
  // Invariant: deregistered service never in getServicesByRole
  // -------------------------------------------------------------------------

  describe("Invariants", function () {
    it("deregistered service is never returned by getServicesByRole", async function () {
      const { serviceRegistry } = await loadFixture(deployAllRegistriesFixture);
      await serviceRegistry.registerService("svc:inv:1", "did:k:a", "http://a", "producer", "");
      await serviceRegistry.registerService("svc:inv:2", "did:k:b", "http://b", "producer", "");
      await serviceRegistry.deregisterService("svc:inv:1");

      const producers = await serviceRegistry.getServicesByRole("producer");
      const ids = producers.map((r: any) => r.serviceId);
      expect(ids).not.to.include("svc:inv:1");
      expect(ids).to.include("svc:inv:2");
    });

    it("IssuerRegistry enumeration invariant: count matches active issuers", async function () {
      const { issuerRegistry } = await loadFixture(deployAllRegistriesFixture);
      await issuerRegistry.registerIssuer("did:k:1", "A", "", "");
      await issuerRegistry.registerIssuer("did:k:2", "B", "", "");
      await issuerRegistry.registerIssuer("did:k:3", "C", "", "");
      expect(await issuerRegistry.getIssuerCount()).to.equal(3n);

      await issuerRegistry.revokeIssuer("did:k:2");
      expect(await issuerRegistry.getIssuerCount()).to.equal(2n);

      // Verify remaining issuers are still iterable
      const r0 = await issuerRegistry.getIssuerAtIndex(0);
      const r1 = await issuerRegistry.getIssuerAtIndex(1);
      expect(r0.active).to.be.true;
      expect(r1.active).to.be.true;
    });

    it("StatusRegistry: stored credentialHash matches published value", async function () {
      const { statusRegistry } = await loadFixture(deployAllRegistriesFixture);
      const hash = ethers.keccak256(ethers.toUtf8Bytes("my-jwt"));
      await statusRegistry.publishStatusAnchor("did:k:issuer", 42n, hash, "https://x.com/s.json", 120n);

      const anchor = await statusRegistry.getStatusAnchor("did:k:issuer", 42n);
      expect(anchor.credentialHash).to.equal(hash);
    });
  });
});
