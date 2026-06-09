// acp-sec test Client (buyer) -- Base Sepolia
//
// Drives a full Client -> Provider -> settlement round-trip against the acp-sec
// Provider for proof. It targets the seller directly by wallet address (no
// reliance on keyword-search ranking), initiates a "scan address X" job, pays
// the escrow on NEGOTIATION, and on COMPLETED captures the deliverable + tx
// references into a proof JSON file.
//
// This is dev/test tooling, not part of the shipped Provider.
//
// Env vars:
//   WHITELISTED_WALLET_PRIVATE_KEY  session signer key (falls back to PRIVATE_KEY)
//   BUYER_AGENT_WALLET_ADDRESS      buyer agent smart-account address
//   BUYER_ENTITY_ID                 integer entity id of the whitelisted key
//   SELLER_AGENT_WALLET_ADDRESS     the acp-sec Provider's smart-account address
//   SCAN_TARGET                     address to scan (default: SentryAgent)
//   PROOF_OUT                       proof output path (default: /tmp/acp-roundtrip-proof.json)
//
// The private key is never logged or printed.

import fs from "node:fs";

import AcpClient, {
  AcpContractClientV2,
  AcpJobPhases,
  baseSepoliaAcpConfigV2,
} from "@virtuals-protocol/acp-node";

const SENTRY_AGENT = "0x7770ED57E3993d4555951a557cd158a6Fb87A470";
const SCAN_TARGET = process.env.SCAN_TARGET || SENTRY_AGENT;
const PROOF_OUT = process.env.PROOF_OUT || "/tmp/acp-roundtrip-proof.json";

function requireEnv(name, fallback) {
  const value = process.env[name] || (fallback ? process.env[fallback] : undefined);
  if (!value || value.trim() === "") {
    throw new Error(`${name}${fallback ? ` (or ${fallback})` : ""} is required but not set`);
  }
  return value;
}

function normalizeKey(key) {
  return key.startsWith("0x") ? key : `0x${key}`;
}

function txRefs(job) {
  // Surface whatever on-chain references the SDK exposes on the job's memos.
  return (job.memos || []).map((m) => ({
    id: m.id,
    type: m.type,
    nextPhase: m.nextPhase,
    txHash: m.txHash,
    signedTxHash: m.signedTxHash,
  }));
}

async function main() {
  const privateKey = normalizeKey(requireEnv("WHITELISTED_WALLET_PRIVATE_KEY", "PRIVATE_KEY"));
  const buyerAddress = requireEnv("BUYER_AGENT_WALLET_ADDRESS");
  const buyerEntityId = parseInt(requireEnv("BUYER_ENTITY_ID"), 10);
  const sellerAddress = requireEnv("SELLER_AGENT_WALLET_ADDRESS");
  if (Number.isNaN(buyerEntityId)) throw new Error("BUYER_ENTITY_ID must be an integer");

  let payTxHash;
  let initiatedJobId;

  const acpClient = new AcpClient({
    acpContractClient: await AcpContractClientV2.build(
      privateKey,
      buyerEntityId,
      buyerAddress,
      baseSepoliaAcpConfigV2,
    ),
    onNewTask: async (job, memoToSign) => {
      try {
        if (
          job.phase === AcpJobPhases.NEGOTIATION &&
          memoToSign?.nextPhase === AcpJobPhases.TRANSACTION
        ) {
          console.log(`[job ${job.id}] NEGOTIATION -- paying escrow...`);
          const res = await job.payAndAcceptRequirement();
          payTxHash = res?.txnHash;
          console.log(`[job ${job.id}] paid (tx ${payTxHash})`);
        } else if (job.phase === AcpJobPhases.COMPLETED) {
          const deliverable = await job.getDeliverable();
          console.log(`[job ${job.id}] COMPLETED. Deliverable:`);
          console.log(JSON.stringify(deliverable, null, 2));
          const proof = {
            chain: "base-sepolia",
            chainId: 84532,
            jobId: job.id,
            buyer: buyerAddress,
            seller: sellerAddress,
            scanTarget: SCAN_TARGET,
            payTxHash,
            deliverable,
            memos: txRefs(job),
            completedAt: new Date().toISOString(),
          };
          fs.writeFileSync(PROOF_OUT, JSON.stringify(proof, null, 2));
          console.log(`Proof written to ${PROOF_OUT}`);
          process.exit(0);
        } else if (job.phase === AcpJobPhases.REJECTED) {
          console.error(`[job ${job.id}] REJECTED by seller: ${job.rejectionReason}`);
          process.exit(1);
        }
      } catch (err) {
        console.error(`[job ${job.id}] client error: ${err.message}`);
      }
    },
  });
  await acpClient.init();

  console.log(`Buyer ${buyerAddress} -> Seller ${sellerAddress}`);
  console.log(`Requesting Trust Score scan of ${SCAN_TARGET}...`);

  const agent = await acpClient.getAgent(sellerAddress, { showHiddenOfferings: true });
  if (!agent) {
    throw new Error(
      `seller agent ${sellerAddress} not found via ACP registry -- is it registered and has it initiated >=1 job?`,
    );
  }
  const offering = agent.jobOfferings?.[0];
  if (!offering) {
    throw new Error(`seller agent ${sellerAddress} has no job offerings`);
  }

  const requirement = {
    address: SCAN_TARGET,
    query: `Run an acp-sec Trust Score scan on ${SCAN_TARGET}`,
  };
  const expiredAt = new Date(Date.now() + 30 * 60 * 1000); // 30 min

  initiatedJobId = await offering.initiateJob(requirement, undefined, expiredAt);
  console.log(`Job ${initiatedJobId} initiated. Waiting for delivery...`);
}

main().catch((err) => {
  console.error(`fatal: ${err.message}`);
  process.exit(1);
});
