#!/usr/bin/env pwsh
# Deploy smart contracts to the local Anvil node running in Docker.
# Uses the hardhat container's network namespace so it can reach anvil on localhost:8545.

Write-Host "Deploying contracts to local Anvil node..." -ForegroundColor Cyan

$result = docker run --rm `
    --network container:connect-hardhat-1 `
    -v "C:/work/doctorat/connect/contracts:/contracts" `
    -v "contracts_node_modules:/contracts/node_modules" `
    -w /contracts `
    node:20-alpine `
    sh -c "npm ci --silent && npx hardhat run scripts/deploy/deploy-local.ts --network localhost"

if ($LASTEXITCODE -eq 0) {
    Write-Host "Contracts deployed successfully." -ForegroundColor Green
} else {
    Write-Host "Deployment failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
