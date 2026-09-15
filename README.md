# T3N Agent Security Gate

A maintainable policy-enforcement agent for T3N enterprise workflows. It decides whether an agent request is allowed, denied, or requires human approval before a sensitive operation runs.

## Why it matters

Enterprise agents need more than authentication. A valid agent can still act for the wrong tenant, invoke an unapproved capability, exceed a budget, replay a request, or use stale authorization. The local policy engine applies explicit policy and emits deterministic SHA-256 audit receipts. The minimal TEE contract enforces the portable action, identity-shape, currency, and budget subset without importing host capabilities.

## Implemented controls

- tenant and agent DID binding
- action allowlist
- resource validation
- integer minor-unit amount validation
- currency and budget binding
- human-approval threshold
- nonce replay rejection
- stale/future timestamp rejection
- deterministic request/decision receipt
- repository secret scanner
- T3N testnet connection adapter with trusted-manifest verification

## Run locally

```bash
npm ci --ignore-scripts
npm test
npm run demo
npm run secret-scan
```

The demo contains no credentials and makes no network requests.

## Connect to T3N testnet

Obtain a fresh challenge-only key from the official claim page. The key is shown once and behaves like an Ethereum signing key. Do not paste it into source, chat, screenshots, build arguments, or public documents.

```bash
npm run t3n:connect
```

The wrapper prompts for the key with hidden input, exports it only to the child process, and unsets it on exit.

The adapter pins `@terminal3/t3n-sdk` to `5.2.0`, calls `fetchTrustedManifest("testnet")`, performs the handshake, and authenticates. It prints only the resulting DID, never the key.

## Decision contract

Input amounts are integer minor units to avoid floating-point ambiguity. Example:

```json
{
  "tenantDid": "did:t3n:tenant-acme",
  "agentDid": "did:t3n:agent-procurement",
  "action": "purchase.reserve",
  "resource": "vendor/acme/order/42",
  "amountMinor": 20000,
  "currency": "USD",
  "nonce": "nonce-00000001",
  "issuedAt": 1000
}
```

The local engine outputs `allow`, `deny`, or `require_approval`, with a reason and tamper-evident receipt ID. TEE contract v0.1.0 returns the decision and reason; durable replay state and receipt storage are explicit production extensions.

## Verified T3N testnet deployment

- Tenant DID: `did:t3n:09ce2cd93d157cd23967b40791d2737d53307b6a`
- Contract: `z:09ce2cd93d157cd23967b40791d2737d53307b6a:security-gate`
- Contract ID: `1038`
- Version: `0.1.0`
- Export: `evaluate-action`
- Host imports: none

Authenticated testnet invocation has verified four outcomes: bounded action `allow`, threshold action `require_approval`, over-budget action `deny`, and unknown action `deny`.

```bash
npm run t3n:register
npm run t3n:invoke
```

## Threat model

The gate assumes T3N authenticates the caller DID and supplies trusted tenant context. It defends against confused-deputy actions, cross-tenant requests, replay, stale requests, undeclared capabilities, and excessive spend. It does not claim to validate business facts supplied by an external vendor. A production deployment should persist nonce state in tenant KV storage and bind approval records to the request receipt.

## Secret hygiene

`.env`, `.next`, `target`, `state.json`, `agent-card.json`, and logs are ignored. `npm run secret-scan` rejects Ethereum-shaped private keys and credential assignments while allowing explicit placeholders. Run it before every public push and inspect Git history separately.

## Challenge handover

The policy engine is dependency-light and independently tested. The contract has been registered and invoked successfully on T3N testnet. Terminal 3 can host the adapter and later move nonce/receipt state into a tenant KV map.

## License

MIT
