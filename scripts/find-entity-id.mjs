// acp-sec — find the on-chain sessionEntityKeyId for each agent
//
// The SDK's AcpContractClientV2.init() accepts an entityId only if, on the
// SingleSignerValidationModule, signers(entityId, agentAccount) == the address
// of the session signer derived from your private key. This script finds that
// integer by probing the same mapping the SDK validates against, so a match here
// is exactly the value that makes init() pass.
//
// Verified against the installed SDK (not old notes):
//   - dist/index.mjs: SINGLE_SIGNER_VALIDATION_MODULE_ADDRESS = 0x0000…7d83 is the
//     ONLY validation-module constant; no "Key Quorum" module exists in the SDK.
//   - V2 init() builds the account with signerEntity:{ entityId } and then calls
//     validateSessionKeyOnChain → readContract signers(uint32,address)→address
//     on that module.
//
// Read-only: this only does eth_call (no transactions, no funds moved).
// Secrets: private keys are read from env, used to derive the public address,
// and NEVER printed or logged. Only derived addresses (public) are shown.
//
// Usage:  set -a && source .env.local && set +a && node scripts/find-entity-id.mjs
//
// Env read:
//   WHITELISTED_WALLET_PRIVATE_KEY + SELLER_AGENT_WALLET_ADDRESS  → SELLER_ENTITY_ID
//   BUYER_WALLET_PRIVATE_KEY       + BUYER_AGENT_WALLET_ADDRESS   → BUYER_ENTITY_ID
// Optional overrides:
//   BASE_SEPOLIA_RPC (default https://sepolia.base.org)
//   SIGNER_MODULE_ADDRESS (default 0x0000…7d83)
//   ENTITY_MAX (default 1024)

import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

// viem lives in the acp_provider package's node_modules (not at repo root).
// Resolve it from there; it resolves to viem's CJS build, so require() it.
const requireProvider = createRequire(
  path.resolve(HERE, "..", "acpsec", "acp_provider", "package.json"),
);
const { createPublicClient, http, isAddress, getAddress } = requireProvider("viem");
const { privateKeyToAccount } = requireProvider("viem/accounts");

// SingleSignerValidationModule — the module the SDK's init() validates against.
const MODULE = (process.env.SIGNER_MODULE_ADDRESS || "0x00000000000099DE0BF6fA90dEB851E2A2df7d83");
const RPC = process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org";
const ENTITY_MAX = Number(process.env.ENTITY_MAX || 1024);
const FIRST_PASS = 256; // probe 0..256 first, then widen to ENTITY_MAX
const ZERO = "0x0000000000000000000000000000000000000000";
const PRIVKEY_RE = /^0x[a-fA-F0-9]{64}$/;

const SIGNERS_ABI = [
  {
    type: "function",
    name: "signers",
    stateMutability: "view",
    inputs: [
      { name: "entityId", type: "uint32" },
      { name: "account", type: "address" },
    ],
    outputs: [{ name: "", type: "address" }],
  },
];

const TARGETS = [
  {
    label: "SELLER",
    keyVar: "WHITELISTED_WALLET_PRIVATE_KEY",
    addrVar: "SELLER_AGENT_WALLET_ADDRESS",
    outVar: "SELLER_ENTITY_ID",
  },
  {
    label: "BUYER",
    keyVar: "BUYER_WALLET_PRIVATE_KEY",
    addrVar: "BUYER_AGENT_WALLET_ADDRESS",
    outVar: "BUYER_ENTITY_ID",
  },
];

const client = createPublicClient({ transport: http(RPC) });

function envOf(name) {
  const v = process.env[name];
  return typeof v === "string" ? v.trim() : "";
}
function normKey(raw) {
  return raw.startsWith("0x") ? raw : `0x${raw}`;
}

// Read signers(entityId, account) with small retry to survive transient RPC 429s.
async function readSigner(entityId, account) {
  let lastErr;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await client.readContract({
        address: MODULE,
        abi: SIGNERS_ABI,
        functionName: "signers",
        args: [entityId, account],
      });
    } catch (err) {
      lastErr = err;
      await new Promise((r) => setTimeout(r, 300 * (attempt + 1)));
    }
  }
  throw lastErr;
}

// Scan entityId 0..ENTITY_MAX for the one whose on-chain signer == signerAddress.
async function findEntityId(signerAddress, account) {
  const want = signerAddress.toLowerCase();
  for (let e = 0; e <= ENTITY_MAX; e++) {
    if (e === FIRST_PASS + 1) {
      console.log(`     …no match in 0..${FIRST_PASS}; widening to ${ENTITY_MAX}…`);
    }
    let onchain;
    try {
      onchain = await readSigner(e, account);
    } catch (err) {
      console.log(`     ⚠️ RPC error at entityId ${e} (skipped): ${err.shortMessage || err.message}`);
      continue;
    }
    if (onchain && onchain.toLowerCase() !== ZERO && onchain.toLowerCase() === want) {
      return e;
    }
  }
  return null;
}

async function processTarget(t) {
  console.log(`\n── ${t.label} ───────────────────────────────`);
  const rawKey = envOf(t.keyVar);
  const rawAddr = envOf(t.addrVar);

  if (!rawKey) {
    console.log(`  ⏳ skip: ${t.keyVar} not set`);
    return;
  }
  if (!rawAddr) {
    console.log(`  ⏳ skip: ${t.addrVar} not set`);
    return;
  }

  const key = normKey(rawKey);
  if (!PRIVKEY_RE.test(key)) {
    console.log(`  ❌ ${t.keyVar} is not a 0x + 64-hex private key — skipping`);
    return;
  }
  if (!isAddress(rawAddr)) {
    console.log(`  ❌ ${t.addrVar}="${rawAddr}" is not a valid address — skipping`);
    return;
  }
  const account = getAddress(rawAddr); // checksummed

  let signerAddress;
  try {
    signerAddress = privateKeyToAccount(key).address; // public address only
  } catch (err) {
    console.log(`  ❌ could not derive address from ${t.keyVar}: ${err.message} — skipping`);
    return;
  }

  // Print ONLY the public address — confirm it matches the wallet you whitelisted.
  console.log(`  signer EOA   : ${signerAddress}`);
  console.log(`     (derived fresh from ${t.keyVar} — confirm this is the address you whitelisted)`);
  console.log(`  agent account: ${account}`);
  console.log(`  probing signers(entityId, account) on module ${MODULE} …`);

  const entityId = await findEntityId(signerAddress, account);
  if (entityId === null) {
    console.log(`  ❌ no entityId in 0..${ENTITY_MAX} maps to this signer on this account.`);
    console.log(`     → Confirm the signer EOA above was whitelisted on THIS smart account,`);
    console.log(`       or decode the original installValidation tx (Basescan) for the uint32 entityId.`);
  } else {
    console.log(`  ✅ match: signers(${entityId}, ${account}) == signer`);
    console.log(`     → set ${t.outVar}=${entityId} in .env.local`);
  }
}

async function main() {
  console.log("acp-sec — sessionEntityKeyId finder");
  console.log("───────────────────────────────────");
  console.log(`module : ${MODULE} (SingleSignerValidationModule)`);
  console.log(`rpc    : ${RPC}`);
  console.log(`range  : 0..${ENTITY_MAX} (read-only eth_call; no transactions)`);

  for (const t of TARGETS) {
    try {
      await processTarget(t);
    } catch (err) {
      console.log(`  ❌ ${t.label}: unexpected error: ${err && err.message ? err.message : err}`);
    }
  }
  console.log("\nDone. Plug any found integer into .env.local and confirm with: node scripts/verify-acp-env.mjs");
  process.exit(0);
}

main().catch((err) => {
  console.error(`\nUnexpected error: ${err && err.stack ? err.stack : err}`);
  process.exit(1);
});
