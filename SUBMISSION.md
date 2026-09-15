# T3N Agent Build Challenge Submission Draft

## Project

**T3N Agent Security Gate: policy enforcement and tamper-evident receipts for enterprise agents**

## One-line pitch

A trusted gate that binds every enterprise-agent action to tenant, agent DID, capability, budget, freshness, and replay policy before execution.

## Problem

Authentication alone does not make autonomous actions safe. A valid agent can invoke the wrong capability, cross tenant boundaries, replay an old request, or exceed an approved budget. Enterprises need a small, auditable decision point that fails closed and explains every outcome.

## Solution

The gate evaluates structured action requests and returns `allow`, `deny`, or `require_approval`. The local policy engine adds a deterministic SHA-256 receipt bound to the complete request and outcome. The deliberately minimal TEE contract returns the decision and reason with no HTTP, KV, secret, logging, or other host imports.

## Security properties demonstrated

- Cross-tenant request: denied
- Unknown agent DID: denied
- Unapproved action: denied
- Replay of a previously evaluated nonce: denied
- Expired or future-dated request: denied
- Non-integer, negative, or over-budget amount: denied
- High-value but in-budget request: requires human approval
- Authorized bounded request: allowed with audit receipt

## Maintenance

The core uses Node's standard library and has no runtime dependency. The T3N adapter pins the official SDK to version 5.2.0. Tests run offline with `node --test`. Secret scanning and generated-artifact exclusions are included. Terminal 3 can host and maintain it; the recommended production extension stores nonce and approval state in tenant KV.

## Evidence to attach

- Public GitHub repository URL: `[ADD AFTER PUBLISHING]`
- Architecture screenshot source: `docs/architecture.html`
- Test evidence: 8/8 Node tests plus 4/4 Rust unit tests and 1/1 Rust doc test
- Authenticated T3N DID: `did:t3n:09ce2cd93d157cd23967b40791d2737d53307b6a`
- Registered contract: `z:09ce2cd93d157cd23967b40791d2737d53307b6a:security-gate`
- Contract ID/version: `1038` / `0.1.0`
- Verified testnet outcomes: `allow`, `require_approval`, `deny` (budget), `deny` (action)
- Screenshot files: `[CAPTURE BEFORE SUBMISSION]`
- Bugs or documentation friction: `[ADD ONLY REPRODUCIBLE ITEMS]`

## Handover preference

We are happy for Terminal 3 to host and maintain the agent after the challenge. Handover includes source, tests, threat model, pinned dependency lockfile, deployment steps, and state-migration notes. No signing key is included in the repository or handover bundle.
