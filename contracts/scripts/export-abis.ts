/**
 * export-abis.ts — copies ABI arrays from Hardhat artifacts to contracts/abis/
 *
 * Run: npx ts-node scripts/export-abis.ts
 * (or: npm run export-abis after compiling with npx hardhat compile)
 *
 * Output files are committed and consumed by the Python web3.py client (TASK-020).
 */

import * as fs from "fs";
import * as path from "path";

const ARTIFACTS_DIR = path.resolve(__dirname, "../artifacts/contracts");
const ABIS_DIR = path.resolve(__dirname, "../abis");

/** Recursively collects all .json files under `dir`, skipping *.dbg.json. */
function collectArtifacts(dir: string): string[] {
  if (!fs.existsSync(dir)) {
    throw new Error(`Artifacts directory not found: ${dir}\nRun 'npx hardhat compile' first.`);
  }
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectArtifacts(fullPath));
    } else if (entry.name.endsWith(".json") && !entry.name.endsWith(".dbg.json")) {
      results.push(fullPath);
    }
  }
  return results;
}

function main(): void {
  fs.mkdirSync(ABIS_DIR, { recursive: true });

  const artifactFiles = collectArtifacts(ARTIFACTS_DIR);
  let exported = 0;

  for (const filePath of artifactFiles) {
    const raw = fs.readFileSync(filePath, "utf-8");
    const artifact = JSON.parse(raw) as { contractName?: string; abi?: unknown[] };

    if (!artifact.abi || artifact.abi.length === 0) {
      continue; // skip interface-only or empty artifacts
    }

    const contractName = artifact.contractName ?? path.basename(filePath, ".json");
    const outputPath = path.join(ABIS_DIR, `${contractName}.abi.json`);
    fs.writeFileSync(outputPath, JSON.stringify(artifact.abi, null, 2));
    console.log(`  exported: ${contractName}.abi.json`);
    exported++;
  }

  console.log(`\nTotal ABIs exported: ${exported} → ${ABIS_DIR}`);
}

main();
