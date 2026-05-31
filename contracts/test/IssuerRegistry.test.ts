import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("IssuerRegistry (TASK-014)", function () {
  let admin: SignerWithAddress;
  let other: SignerWithAddress;
  let ir: any;

  const DID = "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9y84SB5idYrnfo4Sd6";
  const NAME = "Ministry of Interior";
  const DESC = "Test issuer";
  const META = "ipfs://Qm123";

  beforeEach(async function () {
    [admin, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("IssuerRegistry");
    ir = await upgrades.deployProxy(Factory, [admin.address], { kind: "transparent" });
  });

  // ---- Registration --------------------------------------------------------

  it("registers an issuer and reports it active", async function () {
    await ir.registerIssuer(DID, NAME, DESC, META);
    expect(await ir.isIssuerActive(DID)).to.be.true;
  });

  it("emits IssuerRegistered on registration", async function () {
    const didHash = ethers.keccak256(ethers.toUtf8Bytes(DID));
    await expect(ir.registerIssuer(DID, NAME, DESC, META))
      .to.emit(ir, "IssuerRegistered")
      .withArgs(didHash, DID, NAME, admin.address);
  });

  it("stores all fields correctly", async function () {
    await ir.registerIssuer(DID, NAME, DESC, META);
    const rec = await ir.getIssuer(DID);
    expect(rec.did).to.equal(DID);
    expect(rec.name).to.equal(NAME);
    expect(rec.description).to.equal(DESC);
    expect(rec.metadataURI).to.equal(META);
    expect(rec.active).to.be.true;
    expect(rec.registeredAt).to.be.gt(0n);
  });

  it("reverts on duplicate registration with IssuerAlreadyRegistered", async function () {
    await ir.registerIssuer(DID, NAME, DESC, META);
    await expect(ir.registerIssuer(DID, NAME, DESC, META)).to.be.revertedWithCustomError(
      ir, "IssuerAlreadyRegistered"
    );
  });

  it("reverts on empty DID with InvalidDID", async function () {
    await expect(ir.registerIssuer("", NAME, DESC, META)).to.be.revertedWithCustomError(
      ir, "InvalidDID"
    );
  });

  it("blocks non-admin from registering (AccessControl)", async function () {
    await expect(
      ir.connect(other).registerIssuer(DID, NAME, DESC, META)
    ).to.be.revertedWithCustomError(ir, "AccessControlUnauthorizedAccount");
  });

  // ---- Revocation ----------------------------------------------------------

  it("revokeIssuer sets active=false and emits IssuerRevoked", async function () {
    await ir.registerIssuer(DID, NAME, DESC, META);
    const didHash = ethers.keccak256(ethers.toUtf8Bytes(DID));
    await expect(ir.revokeIssuer(DID))
      .to.emit(ir, "IssuerRevoked")
      .withArgs(didHash, DID, admin.address);
    expect(await ir.isIssuerActive(DID)).to.be.false;
  });

  it("reverts on double-revocation with IssuerAlreadyRevoked", async function () {
    await ir.registerIssuer(DID, NAME, DESC, META);
    await ir.revokeIssuer(DID);
    await expect(ir.revokeIssuer(DID)).to.be.revertedWithCustomError(
      ir, "IssuerAlreadyRevoked"
    );
  });

  it("revokeIssuer reverts with IssuerNotFound for unregistered DID", async function () {
    await expect(ir.revokeIssuer(DID)).to.be.revertedWithCustomError(
      ir, "IssuerNotFound"
    );
  });

  // ---- Update --------------------------------------------------------------

  it("updateIssuer changes fields and emits IssuerUpdated", async function () {
    await ir.registerIssuer(DID, NAME, DESC, META);
    const didHash = ethers.keccak256(ethers.toUtf8Bytes(DID));
    await expect(ir.updateIssuer(DID, "New Name", "New Desc", "ipfs://new"))
      .to.emit(ir, "IssuerUpdated")
      .withArgs(didHash, DID, admin.address);
    const rec = await ir.getIssuer(DID);
    expect(rec.name).to.equal("New Name");
    expect(rec.metadataURI).to.equal("ipfs://new");
  });

  // ---- Enumeration ---------------------------------------------------------

  it("getIssuerCount and getIssuerAtIndex work correctly", async function () {
    const DID2 = "did:key:z6Mkabcdef";
    await ir.registerIssuer(DID, NAME, DESC, META);
    await ir.registerIssuer(DID2, "Other", DESC, META);
    expect(await ir.getIssuerCount()).to.equal(2n);
    const rec = await ir.getIssuerAtIndex(0);
    expect(rec.did).to.equal(DID);
  });

  it("revokeIssuer decrements enumeration count", async function () {
    await ir.registerIssuer(DID, NAME, DESC, META);
    await ir.revokeIssuer(DID);
    expect(await ir.getIssuerCount()).to.equal(0n);
  });

  // ---- Pause ---------------------------------------------------------------

  it("pauseRegistry blocks registerIssuer", async function () {
    await ir.pauseRegistry();
    await expect(ir.registerIssuer(DID, NAME, DESC, META)).to.be.revertedWithCustomError(
      ir, "EnforcedPause"
    );
  });

  it("revokeIssuer works even when paused", async function () {
    await ir.registerIssuer(DID, NAME, DESC, META);
    await ir.pauseRegistry();
    await ir.revokeIssuer(DID);
    expect(await ir.isIssuerActive(DID)).to.be.false;
  });

  it("non-admin cannot pause", async function () {
    await expect(ir.connect(other).pauseRegistry()).to.be.revertedWithCustomError(
      ir, "AccessControlUnauthorizedAccount"
    );
  });
});
