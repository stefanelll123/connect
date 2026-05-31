import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("TrustPolicyRegistry (TASK-015)", function () {
  let admin: SignerWithAddress;
  let other: SignerWithAddress;
  let ir: any;
  let tpr: any;

  const ISSUER_DID = "did:key:z6MkIssuer";
  const SERVICE_ID = "svc:weather:prod";
  const CRED_TYPES = ["DriversLicense"];
  const DESC = "Weather service policy";

  beforeEach(async function () {
    [admin, other] = await ethers.getSigners();

    const IRFactory = await ethers.getContractFactory("IssuerRegistry");
    ir = await upgrades.deployProxy(IRFactory, [admin.address], { kind: "transparent" });
    await ir.registerIssuer(ISSUER_DID, "Test Issuer", "desc", "");

    const TPRFactory = await ethers.getContractFactory("TrustPolicyRegistry");
    tpr = await upgrades.deployProxy(TPRFactory, [admin.address, await ir.getAddress()], { kind: "transparent" });
  });

  // ---- createPolicy --------------------------------------------------------

  it("createPolicy stores policy and emits PolicyCreated", async function () {
    const svcHash = ethers.keccak256(ethers.toUtf8Bytes(SERVICE_ID));
    await expect(tpr.createPolicy(SERVICE_ID, [ISSUER_DID], CRED_TYPES, DESC))
      .to.emit(tpr, "PolicyCreated")
      .withArgs(svcHash, SERVICE_ID, 1n, admin.address);

    expect(await tpr.isPolicyActive(SERVICE_ID)).to.be.true;
  });

  it("createPolicy sets version=1 and correct fields", async function () {
    await tpr.createPolicy(SERVICE_ID, [ISSUER_DID], CRED_TYPES, DESC);
    const policy = await tpr.getPolicy(SERVICE_ID);
    expect(policy.version).to.equal(1n);
    expect(policy.serviceId).to.equal(SERVICE_ID);
    expect(policy.allowedIssuerDids[0]).to.equal(ISSUER_DID);
    expect(policy.requiredCredentialTypes[0]).to.equal(CRED_TYPES[0]);
  });

  it("createPolicy reverts if issuer not active in IssuerRegistry (UnknownIssuer)", async function () {
    await expect(
      tpr.createPolicy(SERVICE_ID, ["did:key:z6MkUnknown"], CRED_TYPES, DESC)
    ).to.be.revertedWithCustomError(tpr, "UnknownIssuer");
  });

  it("createPolicy reverts with EmptyAllowedIssuers for empty array", async function () {
    await expect(
      tpr.createPolicy(SERVICE_ID, [], CRED_TYPES, DESC)
    ).to.be.revertedWithCustomError(tpr, "EmptyAllowedIssuers");
  });

  it("createPolicy reverts with PolicyAlreadyExists on duplicate", async function () {
    await tpr.createPolicy(SERVICE_ID, [ISSUER_DID], CRED_TYPES, DESC);
    await expect(
      tpr.createPolicy(SERVICE_ID, [ISSUER_DID], CRED_TYPES, DESC)
    ).to.be.revertedWithCustomError(tpr, "PolicyAlreadyExists");
  });

  // ---- updatePolicy --------------------------------------------------------

  it("updatePolicy increments version and saves previous to history", async function () {
    await tpr.createPolicy(SERVICE_ID, [ISSUER_DID], CRED_TYPES, DESC);

    const DID2 = "did:key:z6MkIssuer2";
    await ir.registerIssuer(DID2, "Issuer 2", "desc", "");

    const svcHash = ethers.keccak256(ethers.toUtf8Bytes(SERVICE_ID));
    await expect(tpr.updatePolicy(SERVICE_ID, [DID2], [], "new desc"))
      .to.emit(tpr, "PolicyUpdated")
      .withArgs(svcHash, SERVICE_ID, 2n, admin.address);

    const current = await tpr.getPolicy(SERVICE_ID);
    expect(current.version).to.equal(2n);
    expect(current.allowedIssuerDids[0]).to.equal(DID2);

    const history = await tpr.getPolicyHistory(SERVICE_ID);
    expect(history.length).to.equal(1);
    expect(history[0].version).to.equal(1n);
    expect(history[0].allowedIssuerDids[0]).to.equal(ISSUER_DID);
  });

  // ---- deactivatePolicy ----------------------------------------------------

  it("deactivatePolicy sets active=false and emits PolicyDeactivated", async function () {
    await tpr.createPolicy(SERVICE_ID, [ISSUER_DID], CRED_TYPES, DESC);
    const svcHash = ethers.keccak256(ethers.toUtf8Bytes(SERVICE_ID));
    await expect(tpr.deactivatePolicy(SERVICE_ID))
      .to.emit(tpr, "PolicyDeactivated")
      .withArgs(svcHash, SERVICE_ID, admin.address);
    expect(await tpr.isPolicyActive(SERVICE_ID)).to.be.false;
  });

  // ---- isIssuerAllowedForService -------------------------------------------

  it("isIssuerAllowedForService returns true for allowed issuer", async function () {
    await tpr.createPolicy(SERVICE_ID, [ISSUER_DID], CRED_TYPES, DESC);
    expect(await tpr.isIssuerAllowedForService(SERVICE_ID, ISSUER_DID)).to.be.true;
  });

  it("isIssuerAllowedForService returns false for disallowed issuer", async function () {
    await tpr.createPolicy(SERVICE_ID, [ISSUER_DID], CRED_TYPES, DESC);
    expect(await tpr.isIssuerAllowedForService(SERVICE_ID, "did:key:z6MkOther")).to.be.false;
  });

  it("isIssuerAllowedForService returns false for inactive policy", async function () {
    await tpr.createPolicy(SERVICE_ID, [ISSUER_DID], CRED_TYPES, DESC);
    await tpr.deactivatePolicy(SERVICE_ID);
    expect(await tpr.isIssuerAllowedForService(SERVICE_ID, ISSUER_DID)).to.be.false;
  });

  // ---- Access control ------------------------------------------------------

  it("non-admin cannot createPolicy", async function () {
    await expect(
      tpr.connect(other).createPolicy(SERVICE_ID, [ISSUER_DID], CRED_TYPES, DESC)
    ).to.be.revertedWithCustomError(tpr, "AccessControlUnauthorizedAccount");
  });

  // ---- Count ---------------------------------------------------------------

  it("getPolicyCount tracks active policies", async function () {
    expect(await tpr.getPolicyCount()).to.equal(0n);
    await tpr.createPolicy(SERVICE_ID, [ISSUER_DID], CRED_TYPES, DESC);
    expect(await tpr.getPolicyCount()).to.equal(1n);
    await tpr.deactivatePolicy(SERVICE_ID);
    expect(await tpr.getPolicyCount()).to.equal(0n);
  });
});
