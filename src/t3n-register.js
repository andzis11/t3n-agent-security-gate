#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import {
  T3nClient,
  TenantClient,
  setEnvironment,
  getNodeUrl,
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

const wasmPath = new URL('../contract/target/wasm32-wasip2/release/t3n_agent_security_gate_contract.wasm', import.meta.url);
const wasm = await readFile(wasmPath);
setEnvironment('testnet');
const wasmComponent = await loadWasmComponent();
const address = eth_get_address(key);
const t3n = new T3nClient({
  trustAnchor: await fetchTrustedManifest('testnet'),
  wasmComponent,
  handlers: { EthSign: metamask_sign(address, undefined, key) },
});
await t3n.handshake();
const auth = await t3n.authenticate(createEthAuthInput(address));
const tenantDid = auth.value;
const tenant = new TenantClient({ t3n, baseUrl: getNodeUrl(), tenantDid });
await tenant.tenant.me();
const result = await tenant.contracts.register({
  tail: 'security-gate',
  version: '0.1.0',
  wasm,
});
const tenantId = tenantDid.slice('did:t3n:'.length);
const deployment = {
  environment: 'testnet',
  tenantDid,
  contractName: `z:${tenantId}:security-gate`,
  contractId: result.contract_id,
  version: '0.1.0',
};
await writeFile(new URL('../deployment.local.json', import.meta.url), `${JSON.stringify(deployment, null, 2)}\n`, { mode: 0o600 });
console.log(JSON.stringify({ registered: true, ...deployment }));
