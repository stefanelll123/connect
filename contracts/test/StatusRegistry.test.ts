import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("StatusRegistry (TASK-016)", function () {
  let admin: SignerWithAddress;
  let publisher: SignerWithAddress;
  let other: SignerWithAddress;
  let ir: any;
  let sr: any;

  const ISSUER_DID = "did:key:z6MkIssuer";
  const STATUS_IDX = 0n;
  const CRED_HASH = ethers.keccak256(ethers.toUtf8Bytes("my-status-list-jwt"));
  const STATUS_URL = "https://example.com/status/0.json";
  const FRESHNESS = 300n; // 5 minutes

  beforeEach(async function () {
    [admin, publisher, other] = await ethers.getSigners();
    const IRFactory = await ethers.getContractFactory("IssuerRegistry");
    ir = await upgrades.deployProxy(IRFactory, [admin.address], { kind: "transparent" });

    const SRFactory = await ethers.getContractFactory("StatusRegistry");
    sr = await upgrades.deployProxy(SRFactory, [admin.address, await ir.getAddress()], { kind: "transparent" });

    // Grant publisher role to second signer
    const PUBLISHER_ROLE = await sr.ANCHOR_PUBLISHER_ROLE();
    await sr.grantRole(PUBLISHER_ROLE, publisher.address);
  });

  // ---- publishStatusAnchor -------------------------------------------------

  it("publishStatusAnchor stores anchor and emits StatusAnchorPublished", async function () {
    const issuerDidHash = ethers.keccak256(ethers.toUtf8Bytes(ISSUER_DID));
    await expect(
      sr.connect(publisher).publishStatusAnchor(
        ISSUER_DID, STATUS_IDX, CRED_HASH, STATUS_URL, FRESHNESS
      )
    )
      .to.emit(sr, "StatusAnchorPublished")
      .withArgs(issuerDidHash, STATUS_IDX, CRED_HASH, STATUS_URL, FRESHNESS);
  });

  it("stores anchor fields correctly", async function () {
    await sr.publishStatusAnchor(ISSUER_DID, STATUS_IDX, CRED_HASH, STATUS_URL, FRESHNESS);
    const anchor = await sr.getStatusAnchor(ISSUER_DID, STATUS_IDX);
    expect(anchor.credentialHash).to.equal(CRED_HASH);
    expect(anchor.statusListUrl).to.equal(STATUS_URL);
    expect(anchor.freshnessDeltaSeconds).to.equal(FRESHNESS);
    expect(anchor.active).to.be.true;
  });

  it("allows updating an existing anchor", async function () {
    await sr.publishStatusAnchor(ISSUER_DID, STATUS_IDX, CRED_HASH, STATUS_URL, FRESHNESS);
    const newHash = ethers.keccak256(ethers.toUtf8Bytes("updated-jwt"));
    await sr.publishStatusAnchor(ISSUER_DID, STATUS_IDX, newHash, STATUS_URL, FRESHNESS);
    const anchor = await sr.getStatusAnchor(ISSUER_DID, STATUS_IDX);
    expect(anchor.credentialHash).to.equal(newHash);
  });

  // ---- freshnessDelta validation -------------------------------------------

  it("reverts with InvalidFreshnessDelta when delta < 60", async function () {
    await expect(
      sr.publishStatusAnchor(ISSUER_DID, STATUS_IDX, CRED_HASH, STATUS_URL, 59n)
    ).to.be.revertedWithCustomError(sr, "InvalidFreshnessDelta");
  });

  it("reverts with InvalidFreshnessDelta when delta > 86400", async function () {
    await expect(
      sr.publishStatusAnchor(ISSUER_DID, STATUS_IDX, CRED_HASH, STATUS_URL, 86401n)
    ).to.be.revertedWithCustomError(sr, "InvalidFreshnessDelta");
  });

  it("accepts delta exactly at MIN_FRESHNESS_DELTA (60)", async function () {
    await expect(
      sr.publishStatusAnchor(ISSUER_DID, STATUS_IDX, CRED_HASH, STATUS_URL, 60n)
    ).not.to.be.reverted;
  });

  it("accepts delta exactly at MAX_FRESHNESS_DELTA (86400)", async function () {
    await expect(
      sr.publishStatusAnchor(ISSUER_DID, STATUS_IDX, CRED_HASH, STATUS_URL, 86400n)
    ).not.to.be.reverted;
  });

  // ---- verifyStatusAnchor --------------------------------------------------

  it("verifyStatusAnchor returns true for matching hash", async function () {
    await sr.publishStatusAnchor(ISSUER_DID, STATUS_IDX, CRED_HASH, STATUS_URL, FRESHNESS);
    expect(await sr.verifyStatusAnchor(ISSUER_DID, STATUS_IDX, CRED_HASH)).to.be.true;
  });

  it("verifyStatusAnchor returns false for wrong hash", async function () {
    await sr.publishStatusAnchor(ISSUER_DID, STATUS_IDX, CRED_HASH, STATUS_URL, FRESHNESS);
    const wrongHash = ethers.keccak256(ethers.toUtf8Bytes("tampered"));
    expect(await sr.verifyStatusAnchor(ISSUER_DID, STATUS_IDX, wrongHash)).to.be.false;
  });

  it("verifyStatusAnchor returns false for nonexistent anchor", async function () {
    expect(await sr.verifyStatusAnchor(ISSUER_DID, STATUS_IDX, CRED_HASH)).to.be.false;
  });

  // ---- getStatusAnchor / AnchorNotFound ------------------------------------

  it("getStatusAnchor reverts AnchorNotFound for nonexistent anchor", async function () {
    await expect(
      sr.getStatusAnchor(ISSUER_DID, STATUS_IDX)
    ).to.be.revertedWithCustomError(sr, "AnchorNotFound");
  });

  // ---- emitEmergencyRevocation ---------------------------------------------

  it("emitEmergencyRevocation emits event without state change", async function () {
    const credHash = ethers.keccak256(ethers.toUtf8Bytes("credential-id-123"));
    await expect(sr.emitEmergencyRevocation(credHash, "key compromise"))
      .to.emit(sr, "EmergencyRevocationEmitted")
      .withArgs(credHash, "key compromise", admin.address);
  });

  it("non-admin cannot emitEmergencyRevocation", async function () {
    const credHash = ethers.keccak256(ethers.toUtf8Bytes("cred-123"));
    await expect(
      sr.connect(other).emitEmergencyRevocation(credHash, "reason")
    ).to.be.revertedWithCustomError(sr, "AccessControlUnauthorizedAccount");
  });

  it("publisher cannot call emitEmergencyRevocation (wrong role)", async function () {
    const credHash = ethers.keccak256(ethers.toUtf8Bytes("cred-456"));
    await expect(
      sr.connect(publisher).emitEmergencyRevocation(credHash, "reason")
    ).to.be.revertedWithCustomError(sr, "AccessControlUnauthorizedAccount");
  });
});
