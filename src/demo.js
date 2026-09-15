import { SecurityGate } from './security-gate.js';

const now = Math.floor(Date.now() / 1000);
const gate = new SecurityGate({
  tenantDid: 'did:t3n:tenant-acme',
  allowedAgents: ['did:t3n:agent-procurement'],
  allowedActions: ['vendor.quote.read', 'purchase.reserve'],
  maxAmountMinor: 100_000,
  currency: 'USD',
  requireApprovalAboveMinor: 50_000,
  nonceTtlSeconds: 300,
}, { now: () => now });

const requests = [
  { label: 'bounded purchase', amountMinor: 20_000, nonce: 'demo-nonce-0001' },
  { label: 'approval threshold', amountMinor: 60_000, nonce: 'demo-nonce-0002' },
  { label: 'over budget', amountMinor: 100_001, nonce: 'demo-nonce-0003' },
  { label: 'unauthorized action', amountMinor: 0, nonce: 'demo-nonce-0004', action: 'secret.export' },
];

for (const item of requests) {
  const result = gate.evaluate({
    tenantDid: 'did:t3n:tenant-acme',
    agentDid: 'did:t3n:agent-procurement',
    action: item.action ?? 'purchase.reserve',
    resource: 'vendor/acme/order/42',
    amountMinor: item.amountMinor,
    currency: 'USD',
    nonce: item.nonce,
    issuedAt: now,
  });
  console.log(JSON.stringify({ label: item.label, ...result }));
}
