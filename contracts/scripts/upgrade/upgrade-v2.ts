import { ethers, upgrades } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * upgrade-v2.ts — Template upgrade script for registry contracts.
 *
 * Prerequisites:
 *   1. ProxyAdmin is owned by TimelockController (set in deploy-proxies.ts).
 *   2. Run `npx hardhat compile` to build the new V2 implementation.
 *   3. Ensure DEPLOYER_PRIVATE_KEY is set in .env (must be a Timelock proposer).
 *
 * Procedure (following upgrade-procedure.md):
 *   Step 1 — Validate storage layout compatibility offline:
 *       npx hardhat run scripts/upgrade/verify-storage-layout.ts
 *   Step 2 — Deploy new implementation (this script handles automatically).
 *   Step 3 — Encode upgrade calldata and submit to TimelockController.schedule().
 *   Step 4 — Wait for TimelockController.getMinDelay() seconds.
 *   Step 5 — Call TimelockController.execute() — anyone can call.
 *
 * Usage:
 *   UPGRADE_CONTRACT=IssuerRegistry \
 *   PROXY_ADDRESS=0x... \
 *   TIMELOCK_ADDRESS=0x... \
 *   npx hardhat run scripts/upgrade/upgrade-v2.ts --network <network>
 */

const UPGRADE_CONTRACT = process.env.UPGRADE_CONTRACT ?? "";
const PROXY_ADDRESS = process.env.PROXY_ADDRESS ?? "";
const TIMELOCK_ADDRESS = process.env.TIMELOCK_ADDRESS ?? "";

async function main(): Promise<void> {
  if (!UPGRADE_CONTRACT || !PROXY_ADDRESS || !TIMELOCK_ADDRESS) {
    throw new Error(
      "Set UPGRADE_CONTRACT, PROXY_ADDRESS, and TIMELOCK_ADDRESS env vars"
    );
  }

  const [proposer] = await ethers.getSigners();
  console.log(`Proposing upgrade as: ${proposer.address}`);
  console.log(`Contract: ${UPGRADE_CONTRACT}  Proxy: ${PROXY_ADDRESS}`);

  // -------------------------------------------------------------------------
  // 1. Deploy new implementation (does NOT upgrade proxy yet)
  // -------------------------------------------------------------------------
  const NewImplFactory = await ethers.getContractFactory(UPGRADE_CONTRACT);
  const newImpl = await upgrades.prepareUpgrade(PROXY_ADDRESS, NewImplFactory, {
    kind: "transparent",
  });
  const newImplAddr = typeof newImpl === "string" ? newImpl : await (newImpl as any).getAddress();
  console.log(`New implementation deployed → ${newImplAddr}`);

  // -------------------------------------------------------------------------
  // 2. Encode upgrade calldata for ProxyAdmin.upgradeAndCall()
  // -------------------------------------------------------------------------
  const proxyAdminAbi = [
    "function upgradeAndCall(address proxy, address implementation, bytes calldata data) payable",
  ];
  const proxyAdminAddr = await upgrades.erc1967.getAdminAddress(PROXY_ADDRESS);
  const proxyAdminIface = new ethers.Interface(proxyAdminAbi);
  const upgradeCalldata = proxyAdminIface.encodeFunctionData("upgradeAndCall", [
    PROXY_ADDRESS,
    newImplAddr,
    "0x", // no additional initializer call needed for simple upgrades
  ]);

  // -------------------------------------------------------------------------
  // 3. Submit proposal to TimelockController
  // -------------------------------------------------------------------------
  const timelockAbi = [
    "function schedule(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt, uint256 delay) external",
    "function getMinDelay() external view returns (uint256)",
    "function execute(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt) payable external",
  ];
  const timelock = new ethers.Contract(TIMELOCK_ADDRESS, timelockAbi, proposer);
  const minDelay = await timelock.getMinDelay();

  const salt = ethers.id(`upgrade-${UPGRADE_CONTRACT}-${Date.now()}`);
  const predecessor = ethers.ZeroHash;

  const tx = await timelock.schedule(
    proxyAdminAddr,
    0n,
    upgradeCalldata,
    predecessor,
    salt,
    minDelay
  );
  await tx.wait();

  console.log(`\nUpgrade scheduled!`);
  console.log(`  TimelockController : ${TIMELOCK_ADDRESS}`);
  console.log(`  Target (ProxyAdmin): ${proxyAdminAddr}`);
  console.log(`  Salt               : ${salt}`);
  console.log(`  Execute after      : ${minDelay}s (~${Number(minDelay) / 3600} hours)`);
  console.log(`\nAfter the delay, call execute() with the same salt to apply the upgrade.`);

  // -------------------------------------------------------------------------
  // 4. Save upgrade history
  // -------------------------------------------------------------------------
  const upgradeRecord = {
    timestamp: new Date().toISOString(),
    contract: UPGRADE_CONTRACT,
    proxy: PROXY_ADDRESS,
    newImplementation: newImplAddr,
    timelockController: TIMELOCK_ADDRESS,
    salt,
    minDelay: minDelay.toString(),
    scheduleTxHash: tx.hash,
  };

  const upgradesDir = path.resolve(__dirname, "../../deployments");
  fs.mkdirSync(upgradesDir, { recursive: true });
  const upgradesPath = path.join(upgradesDir, "upgrades.json");
  const existing = fs.existsSync(upgradesPath)
    ? JSON.parse(fs.readFileSync(upgradesPath, "utf-8"))
    : { upgrades: [] };
  existing.upgrades.push(upgradeRecord);
  fs.writeFileSync(upgradesPath, JSON.stringify(existing, null, 2));
  console.log(`Upgrade record saved to ${upgradesPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
