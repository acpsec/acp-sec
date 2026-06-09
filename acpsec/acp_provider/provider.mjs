// acp-sec ACP Provider (seller) -- Base Sepolia
//
// A thin polling seller loop on top of the official ACP Node SDK
// (@virtuals-protocol/acp-node). It watches for incoming jobs, accepts
// "trust-score scan" requests, runs the scan by shelling out to the Python
// bridge (`python -m acpsec.acp_provider`), and delivers the Trust Score JSON
// through ACP escrow.
//
// Lifecycle handled:
//   REQUEST     -> accept + createRequirement (or reject if no address given)
//   TRANSACTION -> run scan, job.deliver(trustScoreJson)
//   EVALUATION/COMPLETED/REJECTED -> no-op
//
// Env vars (the wallet model is documented in /tmp/acp-sdk-notes.md):
//   WHITELISTED_WALLET_PRIVATE_KEY  session signer key (falls back to PRIVATE_KEY)
//   SELLER_AGENT_WALLET_ADDRESS     the agent's smart-account address
//   SELLER_ENTITY_ID                integer entity id of the whitelisted key
//   ACPSEC_CHAIN                    scan chain flag (default: base-sepolia)
//   ACPSEC_PYTHON                   python executable (default: repo .venv/bin/python)
//   POLL_INTERVAL_MS                poll cadence (default: 20000)
//
// The private key is never logged or printed.

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

import AcpClient, {
  AcpContractClientV2,
  AcpJobPhases,
  baseSepoliaAcpConfigV2,
} from "@virtuals-protocol/acp-node";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..", "..");

const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS || 20000);
const CHAIN = process.env.ACPSEC_CHAIN || "base-sepolia";
const ADDRESS_RE = /0x[a-fA-F0-9]{40}/;

function requireEnv(name, fallback) {
  const value = process.env[name] || (fallback ? process.env[fallback] : undefined);
  if (!value || value.trim() === "") {
    throw new Error(
      `${name}${fallback ? ` (or ${fallback})` : ""} is required but not set`,
    );
  }
  return value;
}

function normalizeKey(key) {
  return key.startsWith("0x") ? key : `0x${key}`;
}

function defaultPython() {
  if (process.env.ACPSEC_PYTHON) return process.env.ACPSEC_PYTHON;
  return path.join(REPO_ROOT, ".venv", "bin", "python");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Run the Python bridge to scan `requirement` and return the deliverable object.
function runScan(requirement) {
  return new Promise((resolve, reject) => {
    const py = defaultPython();
    const reqStr =
      typeof requirement === "string" ? requirement : JSON.stringify(requirement);
    const args = ["-m", "acpsec.acp_provider", reqStr, "--chain", CHAIN];
    const child = spawn(py, args, { cwd: REPO_ROOT });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => {
      let payload;
      try {
        payload = JSON.parse(stdout.trim());
      } catch {
        return reject(
          new Error(`scan bridge produced non-JSON output (exit ${code}): ${stderr.trim()}`),
        );
      }
      if (code !== 0 || payload.error) {
        return reject(new Error(payload.detail || stderr.trim() || `scan exit ${code}`));
      }
      resolve(payload);
    });
  });
}

async function handleJob(job, sellerAddress) {
  if ((job.providerAddress || "").toLowerCase() !== sellerAddress.toLowerCase()) {
    return;
  }
  const phaseName = AcpJobPhases[job.phase];

  if (job.phase === AcpJobPhases.REQUEST) {
    const reqStr =
      typeof job.requirement === "string"
        ? job.requirement
        : JSON.stringify(job.requirement || {});
    const target = (reqStr.match(ADDRESS_RE) || [])[0];
    if (target) {
      console.log(`[job ${job.id}] REQUEST accepted -- target ${target}`);
      await job.accept("acp-sec can run a Trust Score scan on this address.");
      await job.createRequirement(
        `acp-sec accepted job ${job.id}. Pay to escrow to receive the Trust Score for ${target}.`,
      );
    } else {
      console.log(`[job ${job.id}] REQUEST rejected -- no address in requirement`);
      await job.reject(
        'No contract address in request. Send a 0x address, e.g. {"address":"0x..."}.',
      );
    }
    return;
  }

  if (job.phase === AcpJobPhases.TRANSACTION) {
    console.log(`[job ${job.id}] TRANSACTION -- running scan...`);
    try {
      const deliverable = await runScan(job.requirement);
      await job.deliver(deliverable);
      console.log(`[job ${job.id}] delivered: ${deliverable.summary}`);
    } catch (err) {
      console.error(`[job ${job.id}] scan failed: ${err.message}`);
      await job.respond(false, `acp-sec scan failed: ${err.message}`);
    }
    return;
  }

  console.log(`[job ${job.id}] ${phaseName} -- no action`);
}

async function main() {
  const privateKey = normalizeKey(
    requireEnv("WHITELISTED_WALLET_PRIVATE_KEY", "PRIVATE_KEY"),
  );
  const sellerAddress = requireEnv("SELLER_AGENT_WALLET_ADDRESS");
  const entityId = parseInt(requireEnv("SELLER_ENTITY_ID"), 10);
  if (Number.isNaN(entityId)) {
    throw new Error("SELLER_ENTITY_ID must be an integer");
  }

  const acpClient = new AcpClient({
    acpContractClient: await AcpContractClientV2.build(
      privateKey,
      entityId,
      sellerAddress,
      baseSepoliaAcpConfigV2,
    ),
  });
  await acpClient.init();

  console.log(`acp-sec Provider live. Seller ${sellerAddress} on ${CHAIN}.`);
  console.log(`Polling every ${POLL_INTERVAL_MS}ms...`);

  // Dedupe: act at most once per (jobId, phase) to avoid double-submits while a
  // tx is still confirming between polls.
  const handled = new Set();

  while (true) {
    try {
      const jobs = await acpClient.getActiveJobs();
      for (const job of jobs || []) {
        const key = `${job.id}:${job.phase}`;
        if (handled.has(key)) continue;
        handled.add(key);
        try {
          await handleJob(job, sellerAddress);
        } catch (err) {
          console.error(`[job ${job.id}] error: ${err.message}`);
          handled.delete(key); // allow retry next poll
        }
      }
    } catch (err) {
      console.error(`poll error: ${err.message}`);
    }
    await sleep(POLL_INTERVAL_MS);
  }
}

main().catch((err) => {
  console.error(`fatal: ${err.message}`);
  process.exit(1);
});
