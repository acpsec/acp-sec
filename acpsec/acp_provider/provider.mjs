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

import { BoundedSet } from "./boundedSet.mjs";
import { logStartup, installGracefulShutdown } from "./lifecycle.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..", "..");

const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS || 20000);
const CHAIN = process.env.ACPSEC_CHAIN || "base-sepolia";

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

// Invoke the Python bridge (`python -m acpsec.acp_provider <requirement> ...`)
// and resolve its stdout JSON. Rejects on non-JSON output, non-zero exit, or an
// `error` payload. This is the single channel to the Python source of truth.
function runBridge(requirement, extraArgs) {
  return new Promise((resolve, reject) => {
    const py = defaultPython();
    const reqStr =
      typeof requirement === "string" ? requirement : JSON.stringify(requirement);
    const args = ["-m", "acpsec.acp_provider", reqStr, ...extraArgs];
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
          new Error(`bridge produced non-JSON output (exit ${code}): ${stderr.trim()}`),
        );
      }
      if (code !== 0 || payload.error) {
        return reject(new Error(payload.detail || stderr.trim() || `bridge exit ${code}`));
      }
      resolve(payload);
    });
  });
}

// REQUEST phase: ask the Python source of truth whether to accept this job.
// Returns { accept, reason, target } -- both accept and reject resolve (a
// rejection is a valid decision, not an error).
function evaluateRequest(requirement) {
  return runBridge(requirement, ["--mode", "evaluate"]);
}

// TRANSACTION phase: run the Trust Score scan and return the deliverable object.
// The bridge re-derives the target via the same evaluate_request, so the scanned
// address is guaranteed identical to the one accepted at REQUEST time.
function runScan(requirement) {
  return runBridge(requirement, ["--chain", CHAIN]);
}

async function handleJob(job, sellerAddress) {
  if ((job.providerAddress || "").toLowerCase() !== sellerAddress.toLowerCase()) {
    return;
  }
  const phaseName = AcpJobPhases[job.phase];

  if (job.phase === AcpJobPhases.REQUEST) {
    // Decision (parse + accept/reject) comes from the single Python source of
    // truth -- no address parsing lives here anymore.
    const decision = await evaluateRequest(job.requirement);
    if (decision.accept) {
      console.log(`[job ${job.id}] REQUEST accepted -- target ${decision.target}`);
      await job.accept(decision.reason);
      await job.createRequirement(
        `acp-sec accepted job ${job.id}. Pay to escrow to receive the Trust Score for ${decision.target}.`,
      );
    } else {
      console.log(`[job ${job.id}] REQUEST rejected -- ${decision.reason}`);
      await job.reject(decision.reason);
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

  logStartup({
    agent: sellerAddress,        // public smart-account address — fine to log
    chain: CHAIN,
    entityId,                    // public entity id, not key material
    pollIntervalMs: POLL_INTERVAL_MS,
    // NEVER log WHITELISTED_WALLET_PRIVATE_KEY / signer material here
  });

  // Dedupe: act at most once per (jobId, phase) to avoid double-submits while a
  // tx is still confirming between polls. Bounded so a long-running provider
  // doesn't leak memory accumulating every job id it has ever seen.
  const handled = new BoundedSet(1000);

  let running = true; // poll loop continues while true
  let busy = false;   // true while a single job is being processed

  installGracefulShutdown({
    onStop: () => { running = false; },
    isBusy: () => busy,
    cleanup: async () => { /* SDK client has no explicit close; nothing to flush */ },
  });

  while (running) {
    try {
      const jobs = await acpClient.getActiveJobs();
      for (const job of jobs || []) {
        if (!running) break; // stop promptly on shutdown
        const key = `${job.id}:${job.phase}`;
        if (handled.has(key)) continue;
        busy = true;
        try {
          handled.add(key);
          await handleJob(job, sellerAddress);
        } catch (err) {
          console.error(`[job ${job.id}] error: ${err.message}`);
          handled.delete(key); // allow retry next poll
        } finally {
          busy = false;
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
