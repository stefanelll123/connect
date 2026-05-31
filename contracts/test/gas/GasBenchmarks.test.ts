import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-toolbox/network-helpers";

/**
 * TASK-019 — Gas benchmark assertions for all state-changing registry functions.
 *
 * Gas targets (with transparent proxy overhead ~21K gas per call):
 *   registerIssuer   : < 250 000 gas
 *   revokeIssuer     : < 100 000 gas
 *   publishStatusAnchor: < 300 000 gas
 *   registerService  : < 350 000 gas
 *
 * Proxy overhead adds ~21 000 gas per call compared to direct deployment.
 * These limits prevent gas regression from code changes.
 */
describe("GasBenchmarks (TASK-019)", function () {
  async function deployFixture() {
    const [admin] = await ethers.getSigners();

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

    return { admin, issuerRegistry, trustPolicyRegistry, statusRegistry, serviceRegistry };
  }

  // -------------------------------------------------------------------------
  // IssuerRegistry
  // -------------------------------------------------------------------------

  it("registerIssuer: gas < 250 000", async function () {
    const { issuerRegistry } = await loadFixture(deployFixture);
    const tx = await issuerRegistry.registerIssuer(
      "did:key:z6MkGasBench1",
      "Gas Benchmark Issuer",
      "desc",
      ""
    );
    const receipt = await tx.wait();
    const gas = Number(receipt!.gasUsed);
    console.log(`    registerIssuer gas: ${gas}`);
    expect(gas).to.be.lessThan(250_000);
  });

  it("revokeIssuer: gas < 100 000", async function () {
    const { issuerRegistry } = await loadFixture(deployFixture);
    await issuerRegistry.registerIssuer("did:key:z6MkGasBench2", "Issuer", "d", "");
    const tx = await issuerRegistry.revokeIssuer("did:key:z6MkGasBench2");
    const receipt = await tx.wait();
    const gas = Number(receipt!.gasUsed);
    console.log(`    revokeIssuer gas: ${gas}`);
    expect(gas).to.be.lessThan(100_000);
  });

  it("updateIssuer: gas < 100 000", async function () {
    const { issuerRegistry } = await loadFixture(deployFixture);
    await issuerRegistry.registerIssuer("did:key:z6MkGasBench3", "Issuer", "d", "");
    const tx = await issuerRegistry.updateIssuer(
      "did:key:z6MkGasBench3",
      "Updated Name",
      "new desc",
      "ipfs://new"
    );
    const receipt = await tx.wait();
    const gas = Number(receipt!.gasUsed);
    console.log(`    updateIssuer gas: ${gas}`);
    expect(gas).to.be.lessThan(100_000);
  });

  // -------------------------------------------------------------------------
  // TrustPolicyRegistry
  // -------------------------------------------------------------------------

  it("createPolicy (1 issuer): gas < 400 000", async function () {
    const { issuerRegistry, trustPolicyRegistry } = await loadFixture(deployFixture);
    await issuerRegistry.registerIssuer("did:key:gasIssuer", "I", "", "");
    const tx = await trustPolicyRegistry.createPolicy(
      "svc:gas:1",
      ["did:key:gasIssuer"],
      ["Cred"],
      "gas test"
    );
    const receipt = await tx.wait();
    const gas = Number(receipt!.gasUsed);
    console.log(`    createPolicy gas: ${gas}`);
    expect(gas).to.be.lessThan(400_000);
  });

  // -------------------------------------------------------------------------
  // StatusRegistry
  // -------------------------------------------------------------------------

  it("publishStatusAnchor: gas < 300 000", async function () {
    const { statusRegistry } = await loadFixture(deployFixture);
    const credHash = ethers.keccak256(ethers.toUtf8Bytes("jwt"));
    const tx = await statusRegistry.publishStatusAnchor(
      "did:key:gas",
      0n,
      credHash,
      "https://example.com/status/0.json",
      300n
    );
    const receipt = await tx.wait();
    const gas = Number(receipt!.gasUsed);
    console.log(`    publishStatusAnchor gas: ${gas}`);
    expect(gas).to.be.lessThan(300_000);
  });

  // -------------------------------------------------------------------------
  // ServiceRegistry
  // -------------------------------------------------------------------------

  it("registerService: gas < 350 000", async function () {
    const { serviceRegistry } = await loadFixture(deployFixture);
    const tx = await serviceRegistry.registerService(
      "svc:gas:producer",
      "did:key:svc",
      "http://localhost:9000",
      "producer",
      "gas bench"
    );
    const receipt = await tx.wait();
    const gas = Number(receipt!.gasUsed);
    console.log(`    registerService gas: ${gas}`);
    expect(gas).to.be.lessThan(350_000);
  });

  it("deregisterService: gas < 100 000", async function () {
    const { serviceRegistry } = await loadFixture(deployFixture);
    await serviceRegistry.registerService(
      "svc:gas:deregister",
      "did:key:svc2",
      "http://localhost:9001",
      "consumer",
      "dereg bench"
    );
    const tx = await serviceRegistry.deregisterService("svc:gas:deregister");
    const receipt = await tx.wait();
    const gas = Number(receipt!.gasUsed);
    console.log(`    deregisterService gas: ${gas}`);
    expect(gas).to.be.lessThan(100_000);
  });
});
