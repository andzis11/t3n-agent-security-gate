#!/usr/bin/env node
import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { findSecrets } from './secret-scan-lib.js';

const root = new URL('..', import.meta.url).pathname;
const ignored = new Set(['.git', 'node_modules', 'coverage', 'dist', 'target', '.next']);
const extensions = new Set(['.js', '.json', '.md', '.toml', '.wit', '.txt', '.yaml', '.yml']);
const files = [];

async function walk(dir) {
  for (const item of await readdir(dir, { withFileTypes: true })) {
    if (ignored.has(item.name)) continue;
    const path = join(dir, item.name);
    if (item.isDirectory()) await walk(path);
    else if ([...extensions].some((ext) => item.name.endsWith(ext))) files.push(path);
  }
}

await walk(root);
let count = 0;
for (const file of files) {
  const findings = findSecrets(await readFile(file, 'utf8'));
  for (const finding of findings) {
    count += 1;
    console.error(`${relative(root, file)}:${finding.rule}@${finding.offset}`);
  }
}
if (count) process.exit(1);
console.log(`PASS secret scan: ${files.length} text files, 0 findings`);
