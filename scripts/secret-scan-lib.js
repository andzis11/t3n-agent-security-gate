const RULES = [
  {
    name: 'ethereum_private_key',
    pattern: /\b0x[0-9a-fA-F]{64}\b/g,
    ignore: (value) => /^0x0{64}$/i.test(value),
  },
  {
    name: 'credential_assignment',
    pattern: /\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*["']?([^\s"']{8,})["']?/gi,
    ignore: (value) => /(?:<[^>]+>|example|placeholder|your[_-]|process\.env)/i.test(value),
  },
];

export function findSecrets(text) {
  const findings = [];
  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    for (const match of text.matchAll(rule.pattern)) {
      const value = match[0];
      if (!rule.ignore(value)) findings.push({ rule: rule.name, offset: match.index });
    }
  }
  return findings.sort((a, b) => a.offset - b.offset);
}
