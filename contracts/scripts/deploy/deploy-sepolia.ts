import { ethers } from "hardhat";
import * as fs from "fs";
import * as path from "path";

async function main(): Promise<void> {
  const deployerKey = process.env.DEPLOYER_PRIVATE_KEY;
  if (!deployerKey) {
    throw new Error("DEPLOYER_PRIVATE_KEY environment variable is not set. Use a testnet-only key.");
  }

  const [deployer] = await ethers.getSigners();
  console.log(`Deploying to Sepolia with account: ${deployer.address}`);

  const network = await ethers.provider.getNetwork();
  const deployedAt = new Date().toISOString();
  const contracts: Record<string, { address: string; deployedBlock: number; txHash: string }> = {};

  // IssuerRegistry
  const IssuerRegistryFactory = await ethers.getContractFactory("IssuerRegistry");
  const issuerRegistry = await IssuerRegistryFactory.deploy(deployer.address);
  await issuerRegistry.waitForDeployment();
  contracts["IssuerRegistry"] = {
    address: await issuerRegistry.getAddress(),
    deployedBlock: await ethers.provider.getBlockNumber(),
    txHash: issuerRegistry.deploymentTransaction()?.hash ?? "",
  };
  console.log(`IssuerRegistry → ${contracts["IssuerRegistry"].address}`);

  // TrustPolicyRegistry
  const TrustPolicyRegistryFactory = await ethers.getContractFactory("TrustPolicyRegistry");
  const trustPolicyRegistry = await TrustPolicyRegistryFactory.deploy(deployer.address, await issuerRegistry.getAddress());
  await trustPolicyRegistry.waitForDeployment();
  contracts["TrustPolicyRegistry"] = {
    address: await trustPolicyRegistry.getAddress(),
    deployedBlock: await ethers.provider.getBlockNumber(),
    txHash: trustPolicyRegistry.deploymentTransaction()?.hash ?? "",
  };
  console.log(`TrustPolicyRegistry → ${contracts["TrustPolicyRegistry"].address}`);

  // StatusRegistry
  const StatusRegistryFactory = await ethers.getContractFactory("StatusRegistry");
  const statusRegistry = await StatusRegistryFactory.deploy(deployer.address, await issuerRegistry.getAddress());
  await statusRegistry.waitForDeployment();
  contracts["StatusRegistry"] = {
    address: await statusRegistry.getAddress(),
    deployedBlock: await ethers.provider.getBlockNumber(),
    txHash: statusRegistry.deploymentTransaction()?.hash ?? "",
  };
  console.log(`StatusRegistry → ${contracts["StatusRegistry"].address}`);

  // ServiceRegistry
  const ServiceRegistryFactory = await ethers.getContractFactory("ServiceRegistry");
  const serviceRegistry = await ServiceRegistryFactory.deploy(deployer.address);
  await serviceRegistry.waitForDeployment();
  contracts["ServiceRegistry"] = {
    address: await serviceRegistry.getAddress(),
    deployedBlock: await ethers.provider.getBlockNumber(),
    txHash: serviceRegistry.deploymentTransaction()?.hash ?? "",
  };
  console.log(`ServiceRegistry → ${contracts["ServiceRegistry"].address}`);

  const deploymentInfo = {
    network: "sepolia",
    chainId: Number(network.chainId),
    deployedAt,
    deployer: deployer.address,
    contracts,
  };

  const deploymentsDir = path.resolve(__dirname, "../../deployments");
  fs.mkdirSync(deploymentsDir, { recursive: true });
  const outputPath = path.join(deploymentsDir, "sepolia.json");
  fs.writeFileSync(outputPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`\nDeployment info saved to ${outputPath}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
