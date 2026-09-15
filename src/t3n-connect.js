#!/usr/bin/env node
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
  console.error('T3N_API_KEY is missing. Export it locally; never place it in source or chat.');
  process.exit(2);
}

setEnvironment('testnet');
const wasmComponent = await loadWasmComponent();
const address = eth_get_address(key);
const client = new T3nClient({
  trustAnchor: await fetchTrustedManifest('testnet'),
  wasmComponent,
  handlers: { EthSign: metamask_sign(address, undefined, key) },
});

await client.handshake();
const did = await client.authenticate(createEthAuthInput(address));
console.log(JSON.stringify({ connected: true, did: did.value, environment: 'testnet' }));
