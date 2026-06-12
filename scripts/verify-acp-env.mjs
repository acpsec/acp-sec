// acp-sec ACP environment preflight
//
// Runs the Milestone 1 verification ladder (steps 0-5) against the credentials
// in the current environment, IN ORDER, and STOPS at the first hard failure.
//
// Usage (creds loaded from a gitignored .env.local):
//   set -a && source .env.local && set +a && node scripts/verify-acp-env.mjs
//
// Design:
//   - Reads everything from process.env. No secrets are hardcoded here, and no
//     secret value is ever printed (keys are length-checked, never echoed).
//   - Three outcomes per step:
//       PASS    (✅) — verified.
//       PENDING (⏳) — the creds this step needs are not set yet. Printed and
//                      skipped gracefully (NOT a crash) so you can run this after
//                      each browser-registration step to watch progress fill in.
//       FAIL    (❌) — a value IS present but wrong/unusable. Prints an
//                      actionable message and exits 1 immediately.
//   - Network steps (3-5) open a socket via the SDK, so we exit explicitly at
//     the end to avoid hanging the event loop.

import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import fs from "node:fs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

// The SDK lives in the acp_provider package's node_modules, not at repo root.
// Import the bundled ESM entry directly; its transitive deps resolve from the
// co-located node_modules.
const SDK_PATH = path.resolve(
  HERE,
  "..",
  "acpsec",
  "acp_provider",
  "node_modules",
  "@virtuals-protocol",
  "acp-node",
  "dist",
  "index.mjs",
);

// ---- tiny output helpers ---------------------------------------------------

const ADDRESS_RE = /^0x[a-fA-F0-9]{40}$/;
const PRIVKEY_RE = /^0x[a-fA-F0-9]{64}$/;

let pendingCount = 0;

function header(title) {
  console.log(`\n${title}`);
}
function pass(msg) {
  console.log(`  ✅ ${msg}`);
}
function pending(msg) {
  pendingCount += 1;
  console.log(`  ⏳ ${msg}`);
}
function info(msg) {
  console.log(`  •  ${msg}`);
}
function fail(msg, hint) {
  console.log(`  ❌ ${msg}`);
  if (hint) console.log(`     → ${hint}`);
  console.log("\nStopped at first failure. Fix the above and re-run.");
  process.exit(1);
}

// Read an env var with optional fallback name; returns trimmed string or "".
function envOf(name, fallback) {
  const raw = process.env[name] ?? (fallback ? process.env[fallback] : undefined);
  return typeof raw === "string" ? raw.trim() : "";
}

// Required vars for a FULL pass (label -> {name, fallback}).
const REQUIRED = [
  { key: "WHITELISTED_WALLET_PRIVATE_KEY", fallback: "PRIVATE_KEY" },
  { key: "SELLER_AGENT_WALLET_ADDRESS" },
  { key: "SELLER_ENTITY_ID" },
  { key: "BUYER_AGENT_WALLET_ADDRESS" },
  { key: "BUYER_ENTITY_ID" },
  { key: "BASESCAN_API_KEY" },
];

// Parse an entity id exactly as provider.mjs/test_client.mjs do (parseInt base
// 10) and confirm it is a CLEAN integer — this catches the classic mistake of
// pasting the agent registry UUID (e.g. "019eb6be-...") which parseInt silently
// truncates to a wrong number instead of throwing.
function checkEntityId(name) {
  const raw = envOf(name);
  if (!raw) {
    pending(`${name} — pending setup (not set)`);
    return null;
  }
  const n = parseInt(raw, 10);
  const clean = Number.isInteger(n) && String(n) === raw;
  if (!clean) {
    fail(
      `${name} is not a clean integer (got "${raw}" → parseInt → ${n}).`,
      "The SDK needs the numeric sessionEntityKeyId, NOT the agent registry UUID. " +
        "Capture the integer session-key id from the wallet whitelist screen.",
    );
  }
  pass(`${name} = ${n} (clean integer)`);
  return n;
}

function normalizeKey(raw) {
  return raw.startsWith("0x") ? raw : `0x${raw}`;
}

// Build + init an AcpClient for one role; returns the client on success.
// Throws on SDK/whitelist/deploy failure (caller turns it into a FAIL).
async function buildClient(sdk, role, addrVar, entityVar) {
  const { default: AcpClient, AcpContractClientV2, baseSepoliaAcpConfigV2 } = sdk;
  const rawKey = envOf("WHITELISTED_WALLET_PRIVATE_KEY", "PRIVATE_KEY");
  const addr = envOf(addrVar);
  const entityRaw = envOf(entityVar);

  // All three creds must be present to even attempt construction.
  const missing = [];
  if (!rawKey) missing.push("WHITELISTED_WALLET_PRIVATE_KEY");
  if (!addr) missing.push(addrVar);
  if (!entityRaw) missing.push(entityVar);
  if (missing.length) {
    return { status: "pending", missing };
  }

  if (!ADDRESS_RE.test(addr)) {
    fail(`${addrVar}="${addr}" is not a valid 0x smart-account address.`);
  }
  const key = normalizeKey(rawKey);
  if (!PRIVKEY_RE.test(key)) {
    fail(
      `WHITELISTED_WALLET_PRIVATE_KEY is not a 32-byte 0x hex key.`,
      "Expected 0x + 64 hex chars (the session signer EOA private key).",
    );
  }
  const entityId = parseInt(entityRaw, 10); // already validated clean in step 0

  const acpContractClient = await AcpContractClientV2.build(
    key,
    entityId,
    addr,
    baseSepoliaAcpConfigV2,
  );
  const acpClient = new AcpClient({ acpContractClient });
  await acpClient.init();
  return { status: "ok", acpClient };
}

// Turn an SDK error into a targeted hint where we can recognize it.
function explainSdkError(err) {
  const m = (err && err.message ? err.message : String(err)).toLowerCase();
  if (m.includes("deploy")) {
    return "Smart account is not deployed on-chain. Finish wallet creation for this agent in the registry.";
  }
  if (m.includes("session") || m.includes("whitelist") || m.includes("entity")) {
    return "Session key not whitelisted for this entity id. Whitelist the signer EOA and use its numeric sessionEntityKeyId.";
  }
  return "Check the signer key, entity id, and smart-account address for this agent.";
}

// ---- main ladder -----------------------------------------------------------

async function main() {
  console.log("acp-sec ACP env preflight");
  console.log("─────────────────────────");

  // Load the SDK (shared by steps 3-5). If absent, that's a setup FAIL.
  let sdk;
  if (!fs.existsSync(SDK_PATH)) {
    fail(
      `ACP SDK not found at ${SDK_PATH}`,
      "Run: (cd acpsec/acp_provider && npm install)",
    );
  }
  try {
    sdk = await import(pathToFileURL(SDK_PATH).href);
  } catch (err) {
    fail(`Could not load the ACP SDK: ${err.message}`, "Reinstall: (cd acpsec/acp_provider && npm install)");
  }

  // -- Step 0: entity-id integer sanity -------------------------------------
  header("Step 0 — entity-id integer sanity");
  checkEntityId("SELLER_ENTITY_ID");
  checkEntityId("BUYER_ENTITY_ID");

  // -- Step 1: env completeness ---------------------------------------------
  header("Step 1 — env completeness");
  const missing = [];
  for (const { key, fallback } of REQUIRED) {
    const val = envOf(key, fallback);
    if (val) {
      pass(`${key} is set${fallback ? "" : ""}`);
    } else {
      missing.push(key);
      pending(`${key} — pending setup (not set)${fallback ? ` (or ${fallback})` : ""}`);
    }
  }
  if (missing.length) {
    info(`${missing.length} var(s) still pending: ${missing.join(", ")}`);
  }

  // -- Step 2: scan bridge (manual reminder) --------------------------------
  header("Step 2 — scan bridge (run manually)");
  info("This script does not invoke the Python scanner. Verify it separately:");
  info(
    'source .env.local && .venv/bin/python -m acpsec.acp_provider ' +
      '"scan 0x7770ED57E3993d4555951a557cd158a6Fb87A470" --chain base-sepolia',
  );
  info("Expect one JSON deliverable on stdout (type/object/service/value).");

  // -- Step 3: SELLER client constructs + on-chain whitelist verified -------
  header("Step 3 — SELLER client construct + init (on-chain whitelist check)");
  let sellerClient = null;
  {
    let res;
    try {
      res = await buildClient(sdk, "seller", "SELLER_AGENT_WALLET_ADDRESS", "SELLER_ENTITY_ID");
    } catch (err) {
      fail(`Seller client failed to init: ${err.message}`, explainSdkError(err));
    }
    if (res.status === "pending") {
      pending(`seller construction pending — missing: ${res.missing.join(", ")}`);
    } else {
      sellerClient = res.acpClient;
      pass("seller AcpClient constructed and init() passed (smart account deployed, session key whitelisted)");
    }
  }

  // -- Step 4: offering present ---------------------------------------------
  header("Step 4 — seller offering present");
  if (!sellerClient) {
    pending("offering check pending — needs a working seller client (Step 3)");
  } else {
    const sellerAddr = envOf("SELLER_AGENT_WALLET_ADDRESS");
    let agent;
    try {
      agent = await sellerClient.getAgent(sellerAddr, { showHiddenOfferings: true });
    } catch (err) {
      fail(`getAgent failed for seller: ${err.message}`);
    }
    if (!agent) {
      fail(
        `Seller agent not found at ${sellerAddr}.`,
        "Confirm the agent is registered and the address is its smart-account address.",
      );
    }
    const offerings = agent.jobOfferings || [];
    if (offerings.length === 0) {
      fail(
        "Seller agent has 0 job offerings.",
        "Create an offering (schema {address, query}, price $0.01) in the ACP Visualiser.",
      );
    }
    pass(`seller has ${offerings.length} offering(s)`);
    offerings.forEach((o, i) => {
      info(`offering[${i}]: name="${o.name}" price=$${o.price}`);
      if (i === 0 && Number(o.price) !== 0.01) {
        info(`note: offering[0] price is $${o.price}, plan expects $0.01 (not fatal)`);
      }
    });
  }

  // -- Step 5: BUYER client constructs --------------------------------------
  header("Step 5 — BUYER client construct + init");
  {
    let res;
    try {
      res = await buildClient(sdk, "buyer", "BUYER_AGENT_WALLET_ADDRESS", "BUYER_ENTITY_ID");
    } catch (err) {
      fail(`Buyer client failed to init: ${err.message}`, explainSdkError(err));
    }
    if (res.status === "pending") {
      pending(`buyer construction pending — missing: ${res.missing.join(", ")}`);
    } else {
      pass("buyer AcpClient constructed and init() passed (smart account deployed, session key whitelisted)");
    }
  }

  // -- summary --------------------------------------------------------------
  header("Summary");
  if (pendingCount === 0) {
    console.log("  ✅ All preflight checks passed. Ready to attempt a round-trip.");
  } else {
    console.log(`  ⏳ ${pendingCount} item(s) pending setup. No failures. Re-run after the next registration step.`);
  }
  process.exit(0);
}

main().catch((err) => {
  console.error(`\nUnexpected error: ${err && err.stack ? err.stack : err}`);
  process.exit(1);
});
