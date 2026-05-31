import { ethers, upgrades } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main(): Promise<void> {
  const [deployer] = await ethers.getSigners();
  console.log(`Deploying to localhost with account: ${deployer.address}`);

  const network = await ethers.provider.getNetwork();
  const deployedAt = new Date().toISOString();
  const contracts: Record<string, { address: string; deployedBlock: number; txHash: string }> = {};

  const proxyOpts = { kind: "transparent" as const };

  // IssuerRegistry
  const IssuerRegistryFactory = await ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = await upgrades.deployProxy(IssuerRegistryFactory, [deployer.address], proxyOpts);
  await issuerRegistry.waitForDeployment();
  contracts["IssuerRegistry"] = {
    address: await issuerRegistry.getAddress(),
    deployedBlock: await ethers.provider.getBlockNumber(),
    txHash: issuerRegistry.deploymentTransaction()?.hash ?? "",
  };
  console.log(`IssuerRegistry → ${contracts["IssuerRegistry"].address}`);

  // TrustPolicyRegistry
  const TrustPolicyRegistryFactory = await ethers.getContractFactory("TrustPolicyRegistry");
  const trustPolicyRegistry = await upgrades.deployProxy(TrustPolicyRegistryFactory, [deployer.address, await issuerRegistry.getAddress()], proxyOpts);
  await trustPolicyRegistry.waitForDeployment();
  contracts["TrustPolicyRegistry"] = {
    address: await trustPolicyRegistry.getAddress(),
    deployedBlock: await ethers.provider.getBlockNumber(),
    txHash: trustPolicyRegistry.deploymentTransaction()?.hash ?? "",
  };
  console.log(`TrustPolicyRegistry → ${contracts["TrustPolicyRegistry"].address}`);

  // StatusRegistry
  const StatusRegistryFactory = await ethers.getContractFactory("StatusRegistry");
  const statusRegistry = await upgrades.deployProxy(StatusRegistryFactory, [deployer.address, await issuerRegistry.getAddress()], proxyOpts);
  await statusRegistry.waitForDeployment();
  contracts["StatusRegistry"] = {
    address: await statusRegistry.getAddress(),
    deployedBlock: await ethers.provider.getBlockNumber(),
    txHash: statusRegistry.deploymentTransaction()?.hash ?? "",
  };
  console.log(`StatusRegistry → ${contracts["StatusRegistry"].address}`);

  // ServiceRegistry
  const ServiceRegistryFactory = await ethers.getContractFactory("ServiceRegistry");
  const serviceRegistry = await upgrades.deployProxy(ServiceRegistryFactory, [deployer.address], proxyOpts);
  await serviceRegistry.waitForDeployment();
  contracts["ServiceRegistry"] = {
    address: await serviceRegistry.getAddress(),
    deployedBlock: await ethers.provider.getBlockNumber(),
    txHash: serviceRegistry.deploymentTransaction()?.hash ?? "",
  };
  console.log(`ServiceRegistry → ${contracts["ServiceRegistry"].address}`);

  const deploymentInfo = {
    network: "local",
    chainId: Number(network.chainId),
    deployedAt,
    deployer: deployer.address,
    contracts,
  };

  const deploymentsDir = path.resolve(__dirname, "../../deployments");
  fs.mkdirSync(deploymentsDir, { recursive: true });
  const outputPath = path.join(deploymentsDir, "local.json");
  fs.writeFileSync(outputPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`\nDeployment info saved to ${outputPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
