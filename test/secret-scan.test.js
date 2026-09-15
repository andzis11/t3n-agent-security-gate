import test from 'node:test';
import assert from 'node:assert/strict';
import { findSecrets } from '../scripts/secret-scan-lib.js';

test('detects private keys and API-key assignments', () => {
  const findings = findSecrets('T3N_API_KEY=0x' + 'a'.repeat(64) + '\npassword = "hunter2-secret"');
  assert.deepEqual(findings.map((x) => x.rule), ['ethereum_private_key', 'credential_assignment']);
});

test('ignores placeholders and documentation variable names', () => {
  assert.deepEqual(findSecrets('T3N_API_KEY=<set-in-shell>\nprocess.env.T3N_API_KEY\n0x' + '0'.repeat(64)), []);
});
