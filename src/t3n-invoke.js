#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import {
  T3nClient,
  setEnvironment,
  loadWasmComponent,
  fetchTrustedManifest,
  eth_get_address,
  metamask_sign,
  createEthAuthInput,
} from '@terminal3/t3n-sdk';

const key = process.env.T3N_API_KEY;
if (!key) {
  console.error('T3N_API_KEY is missing. Use the secure npm wrapper.');
  process.exit(2);
}

const deployment = JSON.parse(await readFile(new URL('../deployment.local.json', import.meta.url), 'utf8'));
setEnvironment('testnet');
const wasmComponent = await loadWasmComponent();
const address = eth_get_address(key);
const client = new T3nClient({
  trustAnchor: await fetchTrustedManifest('testnet'),
  wasmComponent,
  handlers: { EthSign: metamask_sign(address, undefined, key) },
});
await client.handshake();
const auth = await client.authenticate(createEthAuthInput(address));
if (auth.value !== deployment.tenantDid) throw new Error('authenticated DID does not match deployment tenant');

const base = {
  tenant_did: auth.value,
  agent_did: auth.value,
  resource: 'vendor/acme/order/42',
  currency: 'USD',
};
const cases = [
  { label: 'allow', expected: 'allow', input: { ...base, action: 'purchase.reserve', amount_minor: 20_000, nonce: 'testnet-allow-0001' } },
  { label: 'approval', expected: 'require_approval', input: { ...base, action: 'purchase.reserve', amount_minor: 60_000, nonce: 'testnet-approval-0001' } },
  { label: 'over-budget', expected: 'deny', input: { ...base, action: 'purchase.reserve', amount_minor: 100_001, nonce: 'testnet-budget-0001' } },
  { label: 'unauthorized-action', expected: 'deny', input: { ...base, action: 'secret.export', amount_minor: 0, nonce: 'testnet-action-0001' } },
];
const evidence = [];
for (const item of cases) {
  const result = await client.executeAndDecode({
    contract_id: deployment.contractName,
    contract_version: deployment.version,
    function_name: 'evaluate-action',
    input: item.input,
  });
  if (result.decision !== item.expected) {
    throw new Error(`${item.label}: expected ${item.expected}, got ${result.decision}`);
  }
  evidence.push({ label: item.label, expected: item.expected, result });
  console.log(JSON.stringify({ label: item.label, result }));
}
await writeFile(new URL('../invocation.local.json', import.meta.url), `${JSON.stringify({ deployment, evidence }, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify({ invoked: true, cases: evidence.length, contractId: deployment.contractId }));
