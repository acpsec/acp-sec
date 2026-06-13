# Future Ideas

Parking lot for ideas that surfaced during the build but are deliberately **not** being worked on now. Each entry records the idea, why it's deferred, and the concrete pre-conditions that would have to be true before it earns a place on the roadmap.

This file exists so good ideas aren't lost and bad timing isn't mistaken for a bad idea. Nothing here is a commitment. Adding something here is the *alternative* to executing it during the current phase.

> **Scope-discipline contract:** when a new idea appears mid-phase, it goes here, tagged by the earliest phase it could plausibly belong to — it does not get built in the current phase, however appealing it looks in the moment.

---

## Phase 3 — Multi-agent reasoning layer

**Idea.** Add an AI reasoning layer on top of the deterministic Trust Score engine, to catch vulnerability classes that static analysis structurally misses: logic bugs, semantic flaws, and protocol-level reasoning errors.

**Design constraint (non-negotiable).** The Trust Score must stay deterministic and reproducible. So the reasoning layer follows a *propose-then-confirm* model: the LLM proposes candidate findings, but a deterministic check confirms each one before it affects the score. LLM output never directly moves the number. "Verified findings only."

**Why deferred.** Requires Phase 2 (ACP Provider) to exist first — without a Provider that receives jobs, there's no distribution channel for a deeper analysis tier to plug into. Phase 3 is a value layer on top of Phase 2 distribution, not a standalone.

**Cost note.** Real per-scan LLM cost (token spend), plus dev time to build the verification layer and orchestrate multi-agent flow. Accepted as worth it for the moat — but only after Phase 2 proves the channel.

**Pre-conditions before this moves onto the roadmap:**
- Phase 2 done: Provider live, round-trips working, at least one real job settled over ACP.
- A clear catalog of finding-types the deterministic engine can't reach (so the reasoning layer has a defined job).
- A confirmation mechanism designed for each proposed finding-type (so determinism is preserved).

---

## Phase 3+ — Multi-chain expansion

**Idea.** Extend coverage beyond Base to other chains where agent contracts live.

**Key strategic insight (this is the whole reason it's Phase 3+, not a separate near-term project).** The deterministic Layer-1 of the scanner is intentionally ACP-specific — on Base it checks ERC-8183 / ERC-8004 / ACP lifecycle conformance, and those standards don't exist elsewhere. But the **Phase 3 reasoning layer is chain-agnostic**: an LLM reasoning about a Solidity logic bug doesn't care whether the contract is deployed on Base or on another EVM chain. So multi-chain expansion rides on top of the reasoning layer rather than being a from-scratch rebuild. The reasoning layer is the gateway to multi-chain — not a separate scanner.

**Why deferred.** 
- The competitive moat today *is* ACP/ERC-8183 specificity. On a chain without those standards, that moat evaporates and the tool competes head-on with mature general-purpose tooling (Slither, Foundry, audit firms) in a crowded market.
- Demand is unproven. Decisions of this size shouldn't come from a tiny sample.
- The Virtuals incentive ecosystem (EconomyOS, aGDP positioning, Champion points) is Base-only — expanding elsewhere means leaving that behind for a market with no demonstrated pull yet.

**Pre-conditions before this moves onto the roadmap:**
- Phase 2 done and acp-sec established in the ACP ecosystem (e.g. a meaningful number of public scans, real community awareness).
- Phase 3 reasoning layer mature (it's the transferable component that makes expansion cheap).
- Demand signal from *multiple* independent sources asking for a specific chain — not a single inbound — ideally with willingness to pay.
- Spare capacity to take it on without starving the core.

### Sub-note: Hyperliquid

A trading-agent builder reached out and shared an address that turned out to be a **HyperCore (Hyperliquid) trading EOA** — active perps/spot, ~$37K, EVM balance $0. It is **not** a Base contract, **not** an ACP/ERC-8183 agent, and has no deployed contract code, so acp-sec correctly does not apply (5 of 6 dimensions inapplicable; the 6th, behavioral, would be trading-pattern analysis, not a security audit).

Conclusions recorded so the analysis isn't re-litigated:
- Hyperliquid is a different ecosystem (its own L1 + HyperEVM). HyperEVM is Ethereum-compatible and already served by general tooling (Slither, Foundry) — there's no ERC-8183-shaped gap to fill there.
- "Agent" in trading contexts often means an off-chain bot or API sub-account signing from an EOA — not a deployed contract. Nothing for a contract scanner to analyze.
- This is **not** a trigger to build a separate Hyperliquid scanner. If multi-chain ever happens, it happens via the Phase 3 reasoning layer (above), not a bespoke fork.

**Lightweight action this *did* justify (copy, not scope):** make acp-sec's positioning explicitly ACP-on-Base in the README / X bio / tagline, so misaligned inbound self-filters. That's a 30-minute copy edit, not a scope change, and is the correct response to the misalignment.

---

## Phase 4+ — Telegram bot interface

**Idea.** A Telegram bot front-end: a builder pastes an agent contract address in an ACP-related group, the bot replies with the Trust Score. Meets users where they already are.

**Why deferred.** Pure distribution/UX layer. Worthless until the Provider (Phase 2) and ideally the reasoning depth (Phase 3) exist to back it. Building the interface before the substance is backwards.

**Lessons borrowed from Rick (market-intel bot) — patterns only, NOT features:**
- Telegram-as-interface is a natural distribution channel for crypto builders.
- Freemium maps cleanly onto the existing plan: CLI free/open-source, Provider service paid.
- Concise, scannable output (summary view, not raw JSON) is the right UX for non-technical users.

**Hard boundary.** Rick is *market intelligence* (price, FDV, liquidity, holders); acp-sec is *security audit*. They are different domains and not competitors. Do **not** drift acp-sec toward market-data features to resemble Rick — that dilutes the security focus that is the moat.

**Pre-conditions:** Phase 2 live; a summary output format designed for humans; a hosting story for an always-on bot.

---

## Phase 4+ — Token launch / tokenization

**Idea.** Tokenize the agent on Virtuals.

**Why deferred.** Tokenizing before there's a working product and real utility is pure speculation — easy to dump, brand-damaging if it collapses. Security tooling peers (CertiK, Slither) sell service and reputation, not a token. Tokenizing also can't honestly back a `token` primitive claim until there's a use case.

**Right timing.** After mainnet graduation, once there's a public scan track record and the token can be tied to real utility (e.g. scan discounts, governance over security parameters, staking for a validator role in the Phase 3 multi-agent layer).

**Pre-conditions:** Phase 2 live + mainnet graduation + a concrete, defensible token-utility narrative.

---

## Phase 4+ — Productionization / scaling

Grouped because they share the same gate: only relevant once the Provider is live and carrying enough load to need them. Deferred until then.

- Multi-tenant production hosting; auto-scaling, load balancing, queue workers.
- Durable job persistence (the Phase 2 Provider deliberately uses in-memory + bounded set; persistence is a scaling concern, not an MVP one).
- In-process scan execution to replace the subprocess CLI hop (the double-hop is slower but fine for low volume; optimize only when volume justifies it).
- Parallel job concurrency (Phase 2 is intentionally sequential).
- Monitoring / alerting infra (Sentry, Datadog); analytics dashboard.
- Rate limiting / abuse protection.
- Web dashboard for the operator; public scan-result browser; Trust Score badge embeds.
- Formal SLA / uptime guarantees; ToS / privacy policy; business-entity / KYC setup for monetization.

---

## How to use this file

- New idea mid-phase → add it here under the earliest plausible phase, with a one-line "why deferred" and concrete pre-conditions. Then get back to the current milestone.
- Revisit at each phase boundary: check whether any entry's pre-conditions have actually been met. Only then does it become a candidate for the roadmap.
- An idea living here is not a rejection — it's a scheduling decision.
