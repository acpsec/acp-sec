# acp-sec ACP Provider

Exposes the acp-sec **Trust Score** scanner as an ACP (Agent Commerce Protocol)
**Provider / seller agent** on Base Sepolia. A Client agent submits a
"scan address X" job; this Provider runs the Trust Score scan and delivers the
result JSON, settling through ACP escrow (USDC) on chain.

## Architecture

The ACP job lifecycle runs on the official Node SDK
(`@virtuals-protocol/acp-node`). The thin Node seller loop shells out to a
Python bridge that reuses the existing `acpsec trust-score` engine -- one source
of truth for scoring.

```
Client (buyer)  --ACP job-->  provider.mjs (Node, this dir)
                                   |  TRANSACTION phase
                                   v
                       python -m acpsec.acp_provider <addr>
                                   |  reuses
                                   v
                          acpsec trust-score  ->  Trust Score JSON
                                   |
                                   v
                       job.deliver(JSON)  ->  escrow released
```

- `provider.mjs` -- Node seller loop (polling). `REQUEST` -> accept + create
  requirement; `TRANSACTION` -> run scan + `deliver`.
- `__main__.py` -- Node<->Python bridge; emits one deliverable JSON on stdout.
- `executor.py` -- runs `acpsec trust-score` as a subprocess (Basescan key passed
  via env, never argv).
- `job_logic.py` -- pure, unit-tested: parse scan target, accept/reject, format
  deliverable.
- `test_client.mjs` -- dev/test buyer that drives a full round-trip for proof.

## Wallet model (account abstraction)

`AcpContractClientV2` does not use a bare EOA. It builds an Alchemy Modular
Account V2 *smart account* (gas sponsored) where:

- `*_AGENT_WALLET_ADDRESS` is the deployed **smart-account** address, and
- `WHITELISTED_WALLET_PRIVATE_KEY` is a **session signer** EOA whose address is
  whitelisted on-chain against `*_ENTITY_ID` for that smart account.

These are produced by registering the agent at
<https://app.virtuals.io/acp/join> (create smart wallet, whitelist dev wallet,
fund with test USDC). `init()` hard-fails if the smart account is not deployed
or the session key is not whitelisted.

Base Sepolia (84532) `baseSepoliaAcpConfigV2`: ACP contract
`0xdf54E6Ed6cD1d0632d973ADECf96597b7e87893c`, payment token USDC
`0x036CbD53842c5426634e7929541eC2318f3dCF7e` (6 decimals). Gas is sponsored; ETH
is not required in the agents.

## Setup

```bash
# in this directory
npm install
# scanner deps already installed via:  .venv/bin/pip install -e ".[dev]"
```

## Run the Provider

```bash
export WHITELISTED_WALLET_PRIVATE_KEY=0x...   # session signer (dev wallet)
export SELLER_AGENT_WALLET_ADDRESS=0x...       # acp-sec agent smart account
export SELLER_ENTITY_ID=<int>
export BASESCAN_API_KEY=...                     # required for live scans
node provider.mjs
```

## Run a test round-trip (buyer)

In a second shell, with a funded buyer agent:

```bash
export WHITELISTED_WALLET_PRIVATE_KEY=0x...
export BUYER_AGENT_WALLET_ADDRESS=0x...
export BUYER_ENTITY_ID=<int>
export SELLER_AGENT_WALLET_ADDRESS=0x...        # same as the Provider's
export SCAN_TARGET=0x7770ED57E3993d4555951a557cd158a6Fb87A470  # default: SentryAgent
node test_client.mjs
# on COMPLETED, writes proof to $PROOF_OUT (default /tmp/acp-roundtrip-proof.json)
```

## Bridge contract (for testing without chain)

```bash
.venv/bin/python -m acpsec.acp_provider "scan 0x7770ED57E3993d4555951a557cd158a6Fb87A470" --chain base-sepolia
# -> {"type":"object","service":"acp-sec-trust-score","summary":"...","value":{...}}
```
