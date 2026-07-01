#!/usr/bin/env bash
#
# acp-roundtrip.sh — one full acp-sec Trust Score round-trip on Base MAINNET,
# driven through the acp-cli (Option 2). Buyer creates a job, seller quotes +
# scans + delivers, buyer funds + completes. Writes a proof JSON for the showcase.
#
# ┌─ SAFETY ────────────────────────────────────────────────────────────────┐
# │ Every on-chain acp command is routed through acp_tx(), which FORCES       │
# │ --chain-id 8453 (Base MAINNET) and REFUSES any other --chain-id.          │
# │ ⚠ THIS MOVES REAL USDC. The per-step pauses are your last chance to       │
# │ abort before each on-chain action.                                        │
# └───────────────────────────────────────────────────────────────────────────┘
#
# USAGE (run ONE step at a time so you can approve any browser popup):
#   ./scripts/acp-roundtrip.sh balance       # 0. buyer USDC gate (STOPS if 0)
#   ./scripts/acp-roundtrip.sh create-job    # 1. [buyer]  create job -> JOB_ID
#   ./scripts/acp-roundtrip.sh set-budget    # 2. [seller] propose 0.01 USDC
#   ./scripts/acp-roundtrip.sh fund          # 3. [buyer]  fund 0.01 USDC
#   ./scripts/acp-roundtrip.sh submit        # 4. [seller] scan + submit deliverable
#   ./scripts/acp-roundtrip.sh complete      # 5. [buyer]  approve + release escrow
#   ./scripts/acp-roundtrip.sh status        # show current proof state
#   ./scripts/acp-roundtrip.sh all           # run 0..5 in order, pausing each step
#
# JOB_ID flows between steps via the proof file. Override anytime with: JOB_ID=123
#
# NOTE: requires `acp configure` to have been run already (attended browser auth)
# and the two agents to exist. This script never authenticates or creates agents.

set -uo pipefail

# ── Fixed parameters (review these) ─────────────────────────────────────────
readonly CHAIN_ID=8453                  # Base MAINNET. HARDCODED. REAL FUNDS.
readonly CHAIN_NAME="base-mainnet"      # flag value for the python scanner

readonly SELLER_AGENT_ID="019eb6be-e735-7c42-8bfb-c7f1340f9b88"   # acpsec (seller)
readonly SELLER_WALLET="0x68c20dc9f249505a76cf9d23a6d2973c2cfe4631"
readonly BUYER_AGENT_ID="019ed722-7e2d-71a6-8474-9016a70a716e"    # acpsec_buyer
# Buyer wallet is resolved at runtime via `acp wallet address` (CLI agent
# smart-account; expected to start 0x485c8a20…). Not hardcoded on purpose.

readonly OFFERING="trustScoreScan"
readonly SCAN_TARGET="0x678dC1756b123168f23a698374C000019e38318c"  # teammate agent (dry-run: 76/B)
readonly AMOUNT="0.01"                                              # USDC

# Requirements JSON sent to create-job. MUST match the trustScoreScan offering
# schema you defined in the EconomyOS UI. If create-job fails schema validation,
# adjust the key name here (e.g. "target"/"contractAddress") to match the offering.
readonly REQUIREMENTS="{\"address\":\"${SCAN_TARGET}\"}"

# Base mainnet USDC (for the balance gate). 6 decimals.
readonly USDC_ADDR="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

# ── Paths ────────────────────────────────────────────────────────────────────
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO
readonly PROOF="${REPO}/scans/acp-roundtrip-proof-1.json"
readonly SCAN_FILE="${REPO}/scans/acp-roundtrip-scan-1.json"
readonly PYTHON="${REPO}/.venv/bin/python"

# ── Small helpers ─────────────────────────────────────────────────────────────
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
grn()   { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()   { printf '\033[33m%s\033[0m\n' "$*"; }
die()   { red "ERROR: $*"; exit 1; }

now()   { date -u +%Y-%m-%dT%H:%M:%SZ; }

pause() {
  ylw ""
  ylw ">>> $*"
  ylw ">>> A browser approval popup MAY appear depending on the signer policy."
  read -r -p ">>> Press Enter to run, or Ctrl-C to abort... " _
}

# Run a READ-ONLY acp command (echoed). Adds global --json.
acp_ro() {
  echo "+ acp --json $*" >&2
  acp --json "$@"
}

# Run a STATE-CHANGING on-chain acp command. FORCES --chain-id 8453 (from
# $CHAIN_ID) and refuses any caller-supplied --chain-id so it can't be redirected.
acp_tx() {
  local a
  for a in "$@"; do
    case "$a" in
      --chain-id|--chain-id=*)
        die "acp_tx must not be given --chain-id; it is forced to ${CHAIN_ID}." ;;
    esac
  done
  echo "+ acp --json $* --chain-id ${CHAIN_ID}" >&2
  acp --json "$@" --chain-id "${CHAIN_ID}"
}

use_agent() {  # $1 = agent id, $2 = label
  echo "+ acp agent use --agent-id $1   (${2})" >&2
  acp agent use --agent-id "$1" >/dev/null || die "failed to switch active agent to $2 ($1)"
  grn "active agent -> $2"
}

# proof_set <jq-filter-with-\$v> <json-value>
proof_set() {
  [ -f "$PROOF" ] || echo '{}' > "$PROOF"
  local filter="$1" val="$2" tmp
  tmp="$(mktemp)"
  if jq --argjson v "$val" "$filter" "$PROOF" > "$tmp" 2>/dev/null; then
    mv "$tmp" "$PROOF"
  else
    rm -f "$tmp"; ylw "warn: could not merge into proof ($filter)"
  fi
}
# proof_set_str <jq-filter-with-\$v> <string-value>
proof_set_str() {
  [ -f "$PROOF" ] || echo '{}' > "$PROOF"
  local filter="$1" val="$2" tmp
  tmp="$(mktemp)"
  if jq --arg v "$val" "$filter" "$PROOF" > "$tmp" 2>/dev/null; then
    mv "$tmp" "$PROOF"
  else
    rm -f "$tmp"; ylw "warn: could not merge into proof ($filter)"
  fi
}

# Parse JOB_ID tolerantly from a create-job JSON blob (key name unconfirmed).
extract_job_id() {
  echo "$1" | jq -r '
    .jobId // .id // .job_id // .onChainJobId //
    .data.jobId // .data.id // .job.id // empty' 2>/dev/null
}

get_job_id() {
  local j="${JOB_ID:-}"
  [ -z "$j" ] && [ -f "$PROOF" ] && j="$(jq -r '.jobId // empty' "$PROOF" 2>/dev/null)"
  [ -n "$j" ] || die "no JOB_ID known. Run 'create-job' first, or pass JOB_ID=<id>."
  echo "$j"
}

preflight() {
  command -v acp  >/dev/null || die "acp CLI not found on PATH (npm i -g @virtuals-protocol/acp-cli)"
  command -v jq   >/dev/null || die "jq not found"
  [ -x "$PYTHON" ] || die "venv python not found at $PYTHON"
  mkdir -p "${REPO}/scans"
  [ -f "$PROOF" ] || echo '{}' > "$PROOF"
  # one-time metadata
  proof_set '.meta = ($v + (.meta // {}))' "$(jq -n \
    --arg chain "$CHAIN_NAME" --argjson cid "$CHAIN_ID" \
    --arg sid "$SELLER_AGENT_ID" --arg sw "$SELLER_WALLET" \
    --arg bid "$BUYER_AGENT_ID" --arg off "$OFFERING" \
    --arg tgt "$SCAN_TARGET" --arg amt "$AMOUNT" --arg ts "$(now)" \
    '{chain:$chain, chainId:$cid, seller:{agentId:$sid, wallet:$sw},
      buyer:{agentId:$bid}, offering:$off, scanTarget:$tgt, amount:$amt,
      startedAt:$ts}')"
}

# ── Step 0: buyer USDC balance gate ───────────────────────────────────────────
step_balance() {
  preflight
  use_agent "$BUYER_AGENT_ID" "buyer (acpsec_buyer)"

  echo "+ acp --json wallet address" >&2
  local addr; addr="$(acp wallet address --json 2>/dev/null | jq -r '.address // .wallet // .' 2>/dev/null)"
  grn "buyer wallet: ${addr:-<unknown>}"

  echo "--- buyer balances (Base mainnet) ---"
  local bal_raw; bal_raw="$(acp_ro wallet balance --chain-id "$CHAIN_ID")" || die "balance query failed"
  echo "$bal_raw"

  proof_set '.balanceCheck.raw = $v' "$(echo "$bal_raw" | jq '.' 2>/dev/null || echo 'null')"
  proof_set_str '.balanceCheck.buyerWallet = $v' "${addr:-unknown}"
  proof_set_str '.balanceCheck.at = $v' "$(now)"

  # Best-effort USDC extraction across a few plausible shapes. If we cannot
  # CONFIDENTLY read a positive USDC balance, we STOP rather than risk an
  # unfunded round-trip.
  local usdc
  usdc="$(echo "$bal_raw" | jq -r --arg u "$USDC_ADDR" '
    def lc: ascii_downcase;
    [ ( (.. | objects)
        | select(((.token? // .address? // .contract? // .symbol? // "") | tostring | lc)
                 | (. == ($u|lc)) or (. == "usdc"))
        | (.formatted? // .balance? // .amount? // .value?) )
    ] | map(select(. != null)) | (.[0] // empty)' 2>/dev/null)"

  if [ -z "$usdc" ]; then
    red "Could not parse a USDC balance from the output above."
    red "STOPPING (safety). Eyeball the raw balance: if buyer USDC is 0, fund it."
    red "Fund the buyer wallet (${addr:-0x485c8a20...}) with Base mainnet USDC, then re-run."
    proof_set_str '.balanceCheck.result = $v' "unparseable-stopped"
    exit 1
  fi

  # numeric compare (strip any non-numeric just in case)
  local num; num="$(echo "$usdc" | tr -dc '0-9.' )"
  if awk "BEGIN{exit !(${num:-0} > 0)}"; then
    grn "buyer USDC balance: $usdc  (> 0, ok to proceed)"
    proof_set_str '.balanceCheck.usdc = $v' "$usdc"
    proof_set_str '.balanceCheck.result = $v' "ok"
  else
    red "buyer USDC balance is ${usdc} (zero)."
    red "STOP: fund the buyer wallet ${addr:-0x485c8a20...} with Base mainnet USDC"
    red "      (need >= ${AMOUNT} USDC), then re-run this script."
    proof_set_str '.balanceCheck.usdc = $v' "$usdc"
    proof_set_str '.balanceCheck.result = $v' "zero-stopped"
    exit 1
  fi
}

# ── Step 1: [buyer] create job ────────────────────────────────────────────────
step_create_job() {
  preflight
  use_agent "$BUYER_AGENT_ID" "buyer (acpsec_buyer)"
  pause "STEP 1 [buyer] create-job: offering=${OFFERING} provider=${SELLER_WALLET} requirements=${REQUIREMENTS}"

  local out
  out="$(acp_tx client create-job \
          --provider "$SELLER_WALLET" \
          --offering-name "$OFFERING" \
          --requirements "$REQUIREMENTS")" || die "create-job failed (see output above)"
  echo "$out"

  local jid; jid="$(extract_job_id "$out")"
  proof_set '.steps.createJob.raw = $v' "$(echo "$out" | jq '.' 2>/dev/null || echo 'null')"
  proof_set_str '.steps.createJob.at = $v' "$(now)"

  if [ -z "$jid" ]; then
    red "Could not auto-extract JOB_ID from create-job output above."
    red "Read the job id from the JSON and re-run later steps with JOB_ID=<id>,"
    red "or write it into ${PROOF} under .jobId"
    exit 1
  fi
  proof_set_str '.jobId = $v' "$jid"
  proof_set_str '.steps.createJob.jobId = $v' "$jid"
  grn "JOB_ID = $jid  (saved to proof)"
}

# ── Step 2: [seller] set budget (the provider's "accept" = price quote) ───────
step_set_budget() {
  preflight
  local jid; jid="$(get_job_id)"
  use_agent "$SELLER_AGENT_ID" "seller (acpsec)"
  pause "STEP 2 [seller] set-budget: job=${jid} amount=${AMOUNT} USDC"

  local out
  out="$(acp_tx provider set-budget --job-id "$jid" --amount "$AMOUNT")" \
    || die "set-budget failed (see output above)"
  echo "$out"
  proof_set '.steps.setBudget.raw = $v' "$(echo "$out" | jq '.' 2>/dev/null || echo 'null')"
  proof_set_str '.steps.setBudget.at = $v' "$(now)"
  grn "budget proposed: ${AMOUNT} USDC for job ${jid}"
}

# ── Step 3: [buyer] fund escrow ───────────────────────────────────────────────
step_fund() {
  preflight
  local jid; jid="$(get_job_id)"
  use_agent "$BUYER_AGENT_ID" "buyer (acpsec_buyer)"
  pause "STEP 3 [buyer] fund: job=${jid} amount=${AMOUNT} USDC (moves real testnet USDC into escrow)"

  local out
  out="$(acp_tx client fund --job-id "$jid" --amount "$AMOUNT")" \
    || die "fund failed (see output above)"
  echo "$out"
  proof_set '.steps.fund.raw = $v' "$(echo "$out" | jq '.' 2>/dev/null || echo 'null')"
  proof_set_str '.steps.fund.at = $v' "$(now)"
  grn "funded ${AMOUNT} USDC into escrow for job ${jid}"
}

# ── Step 4: [seller] run the scan, then submit the deliverable ────────────────
step_submit() {
  preflight
  local jid; jid="$(get_job_id)"

  # BASESCAN_API_KEY is required by the python scanner (executor.py). Load it
  # from .env.local without echoing the value.
  local key
  key="$(grep -E '^BASESCAN_API_KEY=' "${REPO}/.env.local" 2>/dev/null | cut -d= -f2- | tr -d '"'"'"'"' )"
  [ -n "$key" ] || die "BASESCAN_API_KEY not found in ${REPO}/.env.local (required for the scan)"

  echo "Running Trust Score scan of ${SCAN_TARGET} on ${CHAIN_NAME}..." >&2
  echo "+ ${PYTHON} -m acpsec.acp_provider \"${SCAN_TARGET}\" --chain ${CHAIN_NAME}" >&2
  local scan
  scan="$( cd "$REPO" && BASESCAN_API_KEY="$key" \
           "$PYTHON" -m acpsec.acp_provider "$SCAN_TARGET" --chain "$CHAIN_NAME" )" \
    || die "scan failed (python bridge exited non-zero)"

  # Validate it's JSON and not an {error:...} payload.
  echo "$scan" | jq -e . >/dev/null 2>&1 || die "scan did not produce JSON: $scan"
  if echo "$scan" | jq -e 'has("error")' >/dev/null 2>&1; then
    die "scan returned an error: $(echo "$scan" | jq -c '{error,detail}')"
  fi
  echo "$scan" > "$SCAN_FILE"
  grn "scan ok -> $SCAN_FILE"
  echo "$scan" | jq '{service, summary}' 2>/dev/null || true
  proof_set '.steps.scan.deliverable = $v' "$scan"
  proof_set_str '.steps.scan.at = $v' "$(now)"

  use_agent "$SELLER_AGENT_ID" "seller (acpsec)"
  pause "STEP 4 [seller] submit deliverable for job=${jid} (delivers the scan JSON on-chain)"

  local out
  out="$(acp_tx provider submit --job-id "$jid" --deliverable "$scan")" \
    || die "submit failed (see output above)"
  echo "$out"
  proof_set '.steps.submit.raw = $v' "$(echo "$out" | jq '.' 2>/dev/null || echo 'null')"
  proof_set_str '.steps.submit.at = $v' "$(now)"
  grn "deliverable submitted for job ${jid}"
}

# ── Step 5: [buyer/evaluator] approve + release escrow ────────────────────────
step_complete() {
  preflight
  local jid; jid="$(get_job_id)"
  use_agent "$BUYER_AGENT_ID" "buyer (acpsec_buyer)"
  pause "STEP 5 [buyer] complete: job=${jid} (releases escrow to the seller)"

  local out
  out="$(acp_tx client complete --job-id "$jid" \
          --reason "acp-sec Trust Score round-trip #1 verified")" \
    || die "complete failed (see output above)"
  echo "$out"
  proof_set '.steps.complete.raw = $v' "$(echo "$out" | jq '.' 2>/dev/null || echo 'null')"
  proof_set_str '.steps.complete.at = $v' "$(now)"
  proof_set_str '.completedAt = $v' "$(now)"
  grn "job ${jid} completed. Proof: ${PROOF}"
}

step_status() {
  [ -f "$PROOF" ] || die "no proof file yet at $PROOF"
  jq '.' "$PROOF"
}

step_all() {
  step_balance
  step_create_job
  step_set_budget
  step_fund
  step_submit
  step_complete
  grn ""
  grn "=== ROUND-TRIP COMPLETE ==="
  grn "Proof:     $PROOF"
  grn "Scan JSON: $SCAN_FILE"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
case "${1:-}" in
  balance)     step_balance ;;
  create-job)  step_create_job ;;
  set-budget)  step_set_budget ;;
  fund)        step_fund ;;
  submit)      step_submit ;;
  complete)    step_complete ;;
  status)      step_status ;;
  all)         step_all ;;
  *)
    sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 1 ;;
esac
