import test from 'node:test';
import assert from 'node:assert/strict';
import { SecurityGate } from '../src/security-gate.js';

const basePolicy = {
  tenantDid: 'did:t3n:tenant-acme',
  allowedAgents: ['did:t3n:agent-procurement'],
  allowedActions: ['vendor.quote.read', 'purchase.reserve'],
  maxAmountMinor: 100_000,
  currency: 'USD',
  requireApprovalAboveMinor: 50_000,
  nonceTtlSeconds: 300,
};

const request = (overrides = {}) => ({
  tenantDid: basePolicy.tenantDid,
  agentDid: basePolicy.allowedAgents[0],
  action: 'purchase.reserve',
  resource: 'vendor/acme/order/42',
  amountMinor: 20_000,
  currency: 'USD',
  nonce: 'nonce-00000001',
  issuedAt: 1_000,
  ...overrides,
});

test('allows an authorized bounded request and returns an audit receipt', () => {
  const gate = new SecurityGate(basePolicy, { now: () => 1_100 });
  const result = gate.evaluate(request());
  assert.equal(result.decision, 'allow');
  assert.match(result.receiptId, /^[a-f0-9]{64}$/);
  assert.equal(result.reason, 'policy_satisfied');
});

test('denies a replayed nonce', () => {
  const gate = new SecurityGate(basePolicy, { now: () => 1_100 });
  assert.equal(gate.evaluate(request()).decision, 'allow');
  const replay = gate.evaluate(request());
  assert.deepEqual({ decision: replay.decision, reason: replay.reason }, {
    decision: 'deny', reason: 'nonce_replayed',
  });
});

test('denies cross-tenant, unknown-agent, and unknown-action requests', () => {
  for (const [change, reason] of [
    [{ tenantDid: 'did:t3n:tenant-other' }, 'tenant_mismatch'],
    [{ agentDid: 'did:t3n:agent-unknown' }, 'agent_not_allowed'],
    [{ action: 'secret.export' }, 'action_not_allowed'],
  ]) {
    const gate = new SecurityGate(basePolicy, { now: () => 1_100 });
    assert.equal(gate.evaluate(request(change)).reason, reason);
  }
});

test('requires approval above threshold and denies over budget', () => {
  const gate = new SecurityGate(basePolicy, { now: () => 1_100 });
  assert.equal(gate.evaluate(request({ amountMinor: 60_000 })).decision, 'require_approval');
  assert.equal(gate.evaluate(request({ nonce: 'nonce-00000002', amountMinor: 100_001 })).reason, 'budget_exceeded');
});

test('denies stale, future, malformed, and non-integer amount requests', () => {
  const cases = [
    [{ issuedAt: 799 }, 'request_expired'],
    [{ issuedAt: 1_131 }, 'request_from_future'],
    [{ nonce: 'short' }, 'invalid_nonce'],
    [{ amountMinor: 1.5 }, 'invalid_amount'],
    [{ amountMinor: -1 }, 'invalid_amount'],
  ];
  for (const [change, reason] of cases) {
    const gate = new SecurityGate(basePolicy, { now: () => 1_100 });
    assert.equal(gate.evaluate(request(change)).reason, reason);
  }
});

test('receipt is deterministic but binds request and decision', () => {
  const a = new SecurityGate(basePolicy, { now: () => 1_100 }).evaluate(request());
  const b = new SecurityGate(basePolicy, { now: () => 1_100 }).evaluate(request());
  const c = new SecurityGate(basePolicy, { now: () => 1_100 }).evaluate(request({ nonce: 'nonce-00000009' }));
  assert.equal(a.receiptId, b.receiptId);
  assert.notEqual(a.receiptId, c.receiptId);
});
