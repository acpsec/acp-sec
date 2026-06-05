const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Deploying with account:", deployer.address);

  const balance = await hre.ethers.provider.getBalance(deployer.address);
  console.log("Account balance:", hre.ethers.formatEther(balance), "ETH");

  const SentryAgent = await hre.ethers.getContractFactory("SentryAgent");
  console.log("Deploying SentryAgent...");

  const contract = await SentryAgent.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log("SentryAgent deployed to:", address);
  console.log("Tx hash:", contract.deploymentTransaction().hash);
  console.log("Explorer: https://sepolia.basescan.org/address/" + address);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
