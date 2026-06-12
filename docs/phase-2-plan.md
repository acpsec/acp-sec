# Phase 2: ACP Provider Build Plan

Reference document for Phase 2 — building the acp-sec **ACP Provider** (seller
agent) so other agents can purchase Trust Score scans over the Agent Commerce
Protocol on Base Sepolia.

> Status: planning. The scanner core is already solid; Phase 2 is the Node
> seller side plus environment/integration work.

---

## 1. Scope

### Definition of Done

**3 successful end-to-end ACP job round-trips** (Client → Provider → scan →
deliver → settle) on the **Base Sepolia sandbox**, each with valid scan output
and completed on-chain settlement.

### Scope IN (7 items)

1. ACP Provider implementation.
2. Job lifecycle handling.
3. Scan executor bridge.
4. Deliverable format.
5. Sandbox round-trip (3×).
6. Error handling.
7. Operator docs.

### Scope OUT (deferred)

- Mainnet deployment
- Multi-tenant hosting
- Multi-agent reasoning (Phase 3)
- Multi-chain (Phase 3+)
- Token launch
- Dynamic pricing
- Web dashboard
- Monitoring infra
- Public launch

### Scope discipline

New ideas that surface during Phase 2 go to **`docs/future-ideas.md`**, tagged by
phase. They are **NOT executed in Phase 2**.

---

## 2. Architecture Decisions

| # | Decision | Choice | Deferred |
|---|----------|--------|----------|
| **A** | Scan execution | **Subprocess CLI call** — keep existing `executor.py`. Single source of truth. | In-process engine import optimization → Phase 4 |
| **B** | Job storage | **In-memory + bounded set** (max size, evict oldest). | Durable persistence → Phase 4 |
| **C** | Concurrency | **Sequential** (1 job at a time). | Parallel → Phase 4 |
| **D** | Error / refund | Scan failure → `job.respond(false, reason)`. | — |

**Decision D caveat:** we **MUST verify in the SDK** whether `respond(false)`
auto-refunds escrow. This is a task in **Milestone 0** — do not assume.

---

## 3. Dependencies & Risks

| # | Sev | Risk | Mitigation |
|---|-----|------|------------|
| 1 | **HIGH** | `acp-node` SDK behavior unknown (refund, polling vs callback, deliver format, phase transitions). | Read SDK source / examples in Milestone 0. |
| 2 | MED | Polling (provider) vs callback (test_client) pattern inconsistency. | Standardize. |
| 3 | MED | Smart-account whitelist. | Verify signer wallet is whitelisted for agent `0x68c20...e4631`. |
| 4 | MED | Buyer test agent. | Register minimal buyer (Opsi B), but first verify in SDK whether EOA + USDC suffices (Opsi A). |
| 5 | LOW | Test USDC. | Via `faucet.circle.com` Base Sepolia. |
| 6 | LOW | Offering setup. | Verify acp-sec needs an offering with schema `{address, query}`, price $0.01. |

**Insight:** Phase 2 is **~50% environment setup/integration + 50% coding**. The
scanner core is well-tested (**865 tests passing**). The work is on the **Node
seller side**.

---

## 4. Task Breakdown (5 Milestones)

### Milestone 0 — SDK Understanding & Environment Audit
Read the SDK + examples → write findings to `/tmp/acp-sdk-notes.md`. Verify:
refund behavior, buyer requirements, polling vs callback, whitelist, offering.
→ **Checkpoint 0**

### Milestone 1 — Environment Setup
Create the offering, whitelist the signer, register the buyer (Opsi B), fund
USDC, capture credentials to `.env.local` (**gitignored**).

### Milestone 2 — Provider Hardening
- Handle `EVALUATION` / `COMPLETED` / `REJECTED` phases.
- Bounded `handled` Set.
- Consolidate accept/reject logic (Node calls Python `evaluate_request`).
- Error / refund per **Decision D**.
- Graceful shutdown + logging.
→ **Checkpoint 2**

### Milestone 3 ⭐ — Round-Trip Testing
- Wire `test_client` with buyer creds.
- Run provider live.
- Debug **round-trip #1** (highest risk).
- Verify proof.
- **Round-trips #2 and #3.**
- Capture proofs to `scans/acp-roundtrip-proof-*.json`.
→ **Checkpoint 3 (HARD):** if stuck **> 1.5 days** on round-trip #1, **stop and
re-evaluate**.

### Milestone 4 — Documentation
Operator README, `.env.example`, Node loop tests, update repo README + showcase
roadmap.

---

## 5. Timeline & Checkpoint Policy

### Timeline — target 4 days, buffer to 6

| Day | Work |
|-----|------|
| Day 1 | M0 + M1 |
| Day 2 | M2 |
| Day 3 | M3 — round-trip #1 |
| Day 4 | M3 — #2 & #3 + M4 |
| Days 5–6 | **Buffer** for round-trip debugging (**NORMAL, not failure**) |

### Checkpoints

- **C0** — SDK / env unknowns resolved.
- **C2** — provider compiles + gaps closed + unit tests green.
- **C3 (HARD)** — round-trip #1 works; if stuck **> 1.5 days**, stop & re-evaluate.
- **DoD** — 3 round-trips + proofs.

### Daily pattern

Read plan → identify today's milestone → work → update progress → commit.
**Stuck > 2 hours on one task → stop, write the blocker, ask.** Don't
brute-force.
