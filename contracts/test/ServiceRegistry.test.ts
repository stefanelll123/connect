import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("ServiceRegistry (TASK-017)", function () {
  let admin: SignerWithAddress;
  let other: SignerWithAddress;
  let srv: any;

  const SVC_ID = "svc:weather:prod";
  const DID = "did:key:z6MkService";
  const URL = "http://localhost:8080"; // http:// allowed on chain 31337
  const ROLE_PRODUCER = "producer";
  const ROLE_CONSUMER = "consumer";
  const DESC = "Weather producer";

  beforeEach(async function () {
    [admin, other] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("ServiceRegistry");
    srv = await upgrades.deployProxy(Factory, [admin.address], { kind: "transparent" });
  });

  // ---- registerService -----------------------------------------------------

  it("registerService stores record and emits ServiceRegistered", async function () {
    const svcHash = ethers.keccak256(ethers.toUtf8Bytes(SVC_ID));
    await expect(srv.registerService(SVC_ID, DID, URL, ROLE_PRODUCER, DESC))
      .to.emit(srv, "ServiceRegistered")
      .withArgs(svcHash, SVC_ID, DID, ROLE_PRODUCER, URL);
    expect(await srv.isServiceActive(SVC_ID)).to.be.true;
  });

  it("stores all fields correctly", async function () {
    await srv.registerService(SVC_ID, DID, URL, ROLE_PRODUCER, DESC);
    const rec = await srv.getService(SVC_ID);
    expect(rec.serviceId).to.equal(SVC_ID);
    expect(rec.did).to.equal(DID);
    expect(rec.baseUrl).to.equal(URL);
    expect(rec.role).to.equal(ROLE_PRODUCER);
    expect(rec.active).to.be.true;
  });

  it("reverts with InvalidRole for unknown role", async function () {
    await expect(
      srv.registerService(SVC_ID, DID, URL, "validator", DESC)
    ).to.be.revertedWithCustomError(srv, "InvalidRole");
  });

  it("reverts with ServiceAlreadyRegistered on duplicate", async function () {
    await srv.registerService(SVC_ID, DID, URL, ROLE_PRODUCER, DESC);
    await expect(
      srv.registerService(SVC_ID, DID, URL, ROLE_PRODUCER, DESC)
    ).to.be.revertedWithCustomError(srv, "ServiceAlreadyRegistered");
  });

  it("reverts with InvalidUrl for empty URL", async function () {
    await expect(
      srv.registerService(SVC_ID, DID, "", ROLE_PRODUCER, DESC)
    ).to.be.revertedWithCustomError(srv, "InvalidUrl");
  });

  it("accepts consumer role", async function () {
    await srv.registerService(SVC_ID, DID, URL, ROLE_CONSUMER, DESC);
    const rec = await srv.getService(SVC_ID);
    expect(rec.role).to.equal(ROLE_CONSUMER);
  });

  // ---- updateService -------------------------------------------------------

  it("updateService changes baseUrl and emits ServiceUpdated", async function () {
    await srv.registerService(SVC_ID, DID, URL, ROLE_PRODUCER, DESC);
    const svcHash = ethers.keccak256(ethers.toUtf8Bytes(SVC_ID));
    const newUrl = "http://localhost:9090";
    await expect(srv.updateService(SVC_ID, newUrl, "updated"))
      .to.emit(srv, "ServiceUpdated")
      .withArgs(svcHash, SVC_ID, newUrl);
    const rec = await srv.getService(SVC_ID);
    expect(rec.baseUrl).to.equal(newUrl);
    expect(rec.description).to.equal("updated");
  });

  it("updateService reverts ServiceNotFound for deregistered service", async function () {
    await srv.registerService(SVC_ID, DID, URL, ROLE_PRODUCER, DESC);
    await srv.deregisterService(SVC_ID);
    await expect(srv.updateService(SVC_ID, URL, DESC)).to.be.revertedWithCustomError(
      srv, "ServiceNotFound"
    );
  });

  // ---- deregisterService ---------------------------------------------------

  it("deregisterService sets active=false and emits ServiceDeregistered", async function () {
    await srv.registerService(SVC_ID, DID, URL, ROLE_PRODUCER, DESC);
    const svcHash = ethers.keccak256(ethers.toUtf8Bytes(SVC_ID));
    await expect(srv.deregisterService(SVC_ID))
      .to.emit(srv, "ServiceDeregistered")
      .withArgs(svcHash, SVC_ID);
    expect(await srv.isServiceActive(SVC_ID)).to.be.false;
  });

  it("deregisterService removes from role index", async function () {
    await srv.registerService(SVC_ID, DID, URL, ROLE_PRODUCER, DESC);
    await srv.deregisterService(SVC_ID);
    const producers = await srv.getServicesByRole(ROLE_PRODUCER);
    expect(producers.length).to.equal(0);
  });

  // ---- getServicesByRole ---------------------------------------------------

  it("getServicesByRole returns only producer services", async function () {
    const SVC2 = "svc:weather:consumer";
    await srv.registerService(SVC_ID, DID, URL, ROLE_PRODUCER, DESC);
    await srv.registerService(SVC2, DID, URL, ROLE_CONSUMER, "consumer");

    const producers = await srv.getServicesByRole(ROLE_PRODUCER);
    const consumers = await srv.getServicesByRole(ROLE_CONSUMER);

    expect(producers.length).to.equal(1);
    expect(producers[0].role).to.equal(ROLE_PRODUCER);
    expect(consumers.length).to.equal(1);
    expect(consumers[0].role).to.equal(ROLE_CONSUMER);
  });

  it("getServicesByRole returns empty array for unknown role", async function () {
    const result = await srv.getServicesByRole("validator");
    expect(result.length).to.equal(0);
  });

  // ---- getServiceCount -----------------------------------------------------

  it("getServiceCount decrements on deregister", async function () {
    await srv.registerService(SVC_ID, DID, URL, ROLE_PRODUCER, DESC);
    expect(await srv.getServiceCount()).to.equal(1n);
    await srv.deregisterService(SVC_ID);
    expect(await srv.getServiceCount()).to.equal(0n);
  });

  // ---- Access control ------------------------------------------------------

  it("non-admin cannot register", async function () {
    await expect(
      srv.connect(other).registerService(SVC_ID, DID, URL, ROLE_PRODUCER, DESC)
    ).to.be.revertedWithCustomError(srv, "AccessControlUnauthorizedAccount");
  });

  // ---- URL validation on local chain (http:// allowed) --------------------

  it("http:// URL is accepted on local chain (31337)", async function () {
    await expect(
      srv.registerService(SVC_ID, DID, "http://sentinel.local:8080", ROLE_PRODUCER, DESC)
    ).not.to.be.reverted;
  });
});
