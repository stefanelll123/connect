import { ethers, upgrades } from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * deploy-proxies.ts — Deploy all four registries as TransparentUpgradeableProxy.
 *
 * Deployment order:
 *   1. IssuerRegistry
 *   2. TrustPolicyRegistry (depends on IssuerRegistry)
 *   3. StatusRegistry      (depends on IssuerRegistry)
 *   4. ServiceRegistry
 *   5. TimelockController  (governs ProxyAdmin)
 *   6. Transfer ProxyAdmin ownership to TimelockController
 */
async function main(): Promise<void> {
  const [deployer] = await ethers.getSigners();
  console.log(`Deploying proxies with account: ${deployer.address}`);

  const network = await ethers.provider.getNetwork();
  const deployedAt = new Date().toISOString();
  const chainId = Number(network.chainId);

  // -------------------------------------------------------------------------
  // 1. IssuerRegistry
  // -------------------------------------------------------------------------
  const IssuerRegistryFactory = await ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = await upgrades.deployProxy(
    IssuerRegistryFactory,
    [deployer.address],
    { kind: "transparent" }
  );
  await issuerRegistry.waitForDeployment();
  const issuerRegistryAddr = await issuerRegistry.getAddress();
  console.log(`IssuerRegistry proxy → ${issuerRegistryAddr}`);

  // -------------------------------------------------------------------------
  // 2. TrustPolicyRegistry
  // -------------------------------------------------------------------------
  const TrustPolicyRegistryFactory = await ethers.getContractFactory("TrustPolicyRegistry");
  const trustPolicyRegistry = await upgrades.deployProxy(
    TrustPolicyRegistryFactory,
    [deployer.address, issuerRegistryAddr],
    { kind: "transparent" }
  );
  await trustPolicyRegistry.waitForDeployment();
  const trustPolicyRegistryAddr = await trustPolicyRegistry.getAddress();
  console.log(`TrustPolicyRegistry proxy → ${trustPolicyRegistryAddr}`);

  // -------------------------------------------------------------------------
  // 3. StatusRegistry
  // -------------------------------------------------------------------------
  const StatusRegistryFactory = await ethers.getContractFactory("StatusRegistry");
  const statusRegistry = await upgrades.deployProxy(
    StatusRegistryFactory,
    [deployer.address, issuerRegistryAddr],
    { kind: "transparent" }
  );
  await statusRegistry.waitForDeployment();
  const statusRegistryAddr = await statusRegistry.getAddress();
  console.log(`StatusRegistry proxy → ${statusRegistryAddr}`);

  // -------------------------------------------------------------------------
  // 4. ServiceRegistry
  // -------------------------------------------------------------------------
  const ServiceRegistryFactory = await ethers.getContractFactory("ServiceRegistry");
  const serviceRegistry = await upgrades.deployProxy(
    ServiceRegistryFactory,
    [deployer.address],
    { kind: "transparent" }
  );
  await serviceRegistry.waitForDeployment();
  const serviceRegistryAddr = await serviceRegistry.getAddress();
  console.log(`ServiceRegistry proxy → ${serviceRegistryAddr}`);

  // -------------------------------------------------------------------------
  // 5. TimelockController (governance)
  // -------------------------------------------------------------------------
  const minDelay = chainId === 31337 || chainId === 11155111 ? 300 : 172800;
  const TimelockFactory = await ethers.getContractFactory("TimelockController");
  const timelock = await TimelockFactory.deploy(
    minDelay,
    [deployer.address],   // proposers: deployer (replace with multisig in production)
    [ethers.ZeroAddress], // executors: anyone can execute after delay
    ethers.ZeroAddress    // admin: none (self-administered timelock)
  );
  await timelock.waitForDeployment();
  const timelockAddr = await timelock.getAddress();
  console.log(`TimelockController → ${timelockAddr} (minDelay: ${minDelay}s)`);

  // -------------------------------------------------------------------------
  // 6. Transfer ProxyAdmin ownership to TimelockController
  // -------------------------------------------------------------------------
  const proxyAdminAddr = await upgrades.erc1967.getAdminAddress(issuerRegistryAddr);
  console.log(`ProxyAdmin → ${proxyAdminAddr}`);

  await upgrades.admin.transferProxyAdminOwnership(issuerRegistryAddr, timelockAddr);
  console.log(`ProxyAdmin ownership transferred to TimelockController`);

  // -------------------------------------------------------------------------
  // 7. Save deployment info
  // -------------------------------------------------------------------------
  const deploymentInfo = {
    network: network.name,
    chainId,
    deployedAt,
    deployer: deployer.address,
    governance: {
      timelockController: timelockAddr,
      minimumDelay: minDelay,
      proxyAdmin: proxyAdminAddr,
    },
    contracts: {
      IssuerRegistry: { proxy: issuerRegistryAddr },
      TrustPolicyRegistry: { proxy: trustPolicyRegistryAddr },
      StatusRegistry: { proxy: statusRegistryAddr },
      ServiceRegistry: { proxy: serviceRegistryAddr },
    },
  };

  const deploymentsDir = path.resolve(__dirname, "../../deployments");
  fs.mkdirSync(deploymentsDir, { recursive: true });
  const outputPath = path.join(deploymentsDir, `${network.name}-proxies.json`);
  fs.writeFileSync(outputPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`\nDeployment info saved to ${outputPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
