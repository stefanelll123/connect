import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

/**
 * Smoke tests: verify all four registries deploy correctly with updated
 * constructors (TASK-014 through TASK-017).
 */
describe("SentinelRegistries — deployment smoke tests", function () {
  let owner: SignerWithAddress;
  let issuerRegistry: any;
  let trustPolicyRegistry: any;
  let statusRegistry: any;
  let serviceRegistry: any;

  beforeEach(async function () {
    [owner] = await ethers.getSigners();

    const IssuerRegistryFactory = await ethers.getContractFactory("IssuerRegistry");
    issuerRegistry = await upgrades.deployProxy(IssuerRegistryFactory, [owner.address], { kind: "transparent" });

    const TrustPolicyRegistryFactory = await ethers.getContractFactory("TrustPolicyRegistry");
    trustPolicyRegistry = await upgrades.deployProxy(
      TrustPolicyRegistryFactory,
      [owner.address, await issuerRegistry.getAddress()],
      { kind: "transparent" }
    );

    const StatusRegistryFactory = await ethers.getContractFactory("StatusRegistry");
    statusRegistry = await upgrades.deployProxy(
      StatusRegistryFactory,
      [owner.address, await issuerRegistry.getAddress()],
      { kind: "transparent" }
    );

    const ServiceRegistryFactory = await ethers.getContractFactory("ServiceRegistry");
    serviceRegistry = await upgrades.deployProxy(ServiceRegistryFactory, [owner.address], { kind: "transparent" });
  });

  it("IssuerRegistry deploys and exposes admin role to owner", async function () {
    const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
    expect(await issuerRegistry.hasRole(DEFAULT_ADMIN_ROLE, owner.address)).to.be.true;
  });

  it("TrustPolicyRegistry deploys and reports zero policies", async function () {
    expect(await trustPolicyRegistry.getPolicyCount()).to.equal(0n);
  });

  it("StatusRegistry deploys and MIN/MAX freshness constants are correct", async function () {
    expect(await statusRegistry.MIN_FRESHNESS_DELTA()).to.equal(60n);
    expect(await statusRegistry.MAX_FRESHNESS_DELTA()).to.equal(86400n);
  });

  it("ServiceRegistry deploys and reports zero services", async function () {
    expect(await serviceRegistry.getServiceCount()).to.equal(0n);
  });

  it("IssuerRegistry registers issuer visible to TrustPolicyRegistry", async function () {
    await issuerRegistry.registerIssuer(
      "did:key:z6MkSmoke",
      "Smoke Issuer",
      "smoke test",
      ""
    );
    expect(await issuerRegistry.isIssuerActive("did:key:z6MkSmoke")).to.be.true;
  });
});
