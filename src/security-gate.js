import { createHash } from 'node:crypto';

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function receiptId(request, decision, reason) {
  return createHash('sha256')
    .update(canonical({ decision, reason, request }))
    .digest('hex');
}

export class SecurityGate {
  #policy;
  #now;
  #seenNonces = new Set();

  constructor(policy, options = {}) {
    this.#policy = structuredClone(policy);
    this.#now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  evaluate(request) {
    const decision = this.#decide(request);
    if (decision.reason !== 'invalid_nonce' && !this.#seenNonces.has(request.nonce)) {
      this.#seenNonces.add(request.nonce);
    }
    return {
      ...decision,
      receiptId: receiptId(request, decision.decision, decision.reason),
    };
  }

  #decide(request) {
    if (!request || typeof request !== 'object') return deny('invalid_request');
    if (request.tenantDid !== this.#policy.tenantDid) return deny('tenant_mismatch');
    if (!this.#policy.allowedAgents.includes(request.agentDid)) return deny('agent_not_allowed');
    if (!this.#policy.allowedActions.includes(request.action)) return deny('action_not_allowed');
    if (typeof request.resource !== 'string' || request.resource.length < 3) return deny('invalid_resource');
    if (!Number.isSafeInteger(request.amountMinor) || request.amountMinor < 0) return deny('invalid_amount');
    if (request.currency !== this.#policy.currency) return deny('currency_mismatch');
    if (typeof request.nonce !== 'string' || !/^[A-Za-z0-9_-]{12,128}$/.test(request.nonce)) return deny('invalid_nonce');
    if (this.#seenNonces.has(request.nonce)) return deny('nonce_replayed');
    if (!Number.isSafeInteger(request.issuedAt)) return deny('invalid_timestamp');

    const now = this.#now();
    if (request.issuedAt < now - this.#policy.nonceTtlSeconds) return deny('request_expired');
    if (request.issuedAt > now + 30) return deny('request_from_future');
    if (request.amountMinor > this.#policy.maxAmountMinor) return deny('budget_exceeded');
    if (request.amountMinor > this.#policy.requireApprovalAboveMinor) {
      return { decision: 'require_approval', reason: 'approval_threshold_exceeded' };
    }
    return { decision: 'allow', reason: 'policy_satisfied' };
  }
}

function deny(reason) {
  return { decision: 'deny', reason };
}
