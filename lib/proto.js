// Shared protocol constants + helpers for the agent cloud.
// Zero dependencies — used by the control plane, node-host, signer, and CLI.

export const PROTO_VERSION = 2;

// Agent lifecycle states (control-plane authoritative).
export const STATE = {
  PENDING: 'pending', // created, not yet scheduled
  SCHEDULED: 'scheduled', // assigned to a node, not yet confirmed running
  RUNNING: 'running', // node confirms it's up
  STOPPING: 'stopping', // drain requested
  STOPPED: 'stopped', // not running (by request)
  FAILED: 'failed', // crashed / node lost
};

// Custody is ONE mechanism, not a spectrum: the signing key lives off-box in the
// signer (see signer/server.js), never on the operator node — so for FUNDS any live node is safe.
// The remaining placement constraint is the HOST's safety: a node only accepts a bundle it can
// sandbox (AGENT_BUNDLES.md §5.6). A node advertises caps.sandbox; built-in workloads have no
// requirement (run anywhere); a 'node'-runtime bundle needs the curated-env+cgroup sandbox; an 'oci'
// (untrusted) bundle needs a container node.
export const SANDBOX_RANK = { none: 0, node: 1, oci: 2 };

export function nodeSatisfies(node, agent) {
  const b = agent?.spec?.bundle;
  if (!b) return true; // built-in workload — no sandbox requirement
  const need = (b.runtime || b.manifest?.runtime) === 'oci' ? SANDBOX_RANK.oci : SANDBOX_RANK.node;
  const have = SANDBOX_RANK[node?.caps?.sandbox] ?? 0;
  return have >= need;
}

// The owner's trading limits — enforced by the signer on every intent. Only
// buy|sell exist; there is no transfer/withdraw, so value can never leave the
// agent wallet through the autonomous path. Keep these conservative by default.
export const DEFAULT_POLICY = {
  maxNotionalSol: 0.05, // largest single trade
  maxDailySol: 0.5, // total per UTC day
  cooldownMs: 30000, // min spacing between trades
  allow: ['buy', 'sell'],
  denyTokens: [], // never trade these mints
  allowTokens: null, // null = any mint; or an array to restrict
  paper: true, // paper by default — fund + set false to go live
  requireVerifiedIntent: false, // when true, sign only verified intents (see normalizeVerified)
};

export function normalizePolicy(p = {}) {
  const n = { ...DEFAULT_POLICY, ...p };
  n.maxNotionalSol = Math.max(0, Number(n.maxNotionalSol) || 0);
  n.maxDailySol = Math.max(n.maxNotionalSol, Number(n.maxDailySol) || 0);
  n.cooldownMs = Math.max(0, Number(n.cooldownMs) || 0);
  n.allow = (Array.isArray(n.allow) ? n.allow : ['buy', 'sell']).filter((k) => k === 'buy' || k === 'sell');
  n.denyTokens = Array.isArray(n.denyTokens) ? n.denyTokens : [];
  n.allowTokens = Array.isArray(n.allowTokens) ? n.allowTokens : null;
  n.paper = n.paper !== false;
  n.requireVerifiedIntent = n.requireVerifiedIntent === true;
  return n;
}

// Verified-intent config (docs/VERIFIED_INTENTS.md). When a policy sets
// requireVerifiedIntent, the signer signs a trade only if the owner-committed `rule`
// re-derives that exact trade from AUTHENTICATED inputs — closing host trade-forgery
// even though the agent runs on someone else's CPU. `acceptedKeys` maps a producer's
// ed25519 public key (raw hex) → the evidence class it is trusted to sign:
// 'data' (first-party signed quotes) or 'inference' (signed model receipts).
export function normalizeRule(rule) {
  if (!rule || typeof rule !== 'object') return null;
  return {
    id: String(rule.id || ''),
    when: Array.isArray(rule.when)
      ? rule.when.map((c) => ({ input: String(c.input), op: String(c.op), value: c.value }))
      : [],
    then: rule.then && typeof rule.then === 'object' ? { ...rule.then } : { kind: 'buy' },
    requires: Array.isArray(rule.requires) ? rule.requires.map(String) : [],
  };
}

export function normalizeVerified(v = {}) {
  return {
    rule: v.rule ? normalizeRule(v.rule) : null,
    acceptedKeys:
      v.acceptedKeys && typeof v.acceptedKeys === 'object' && !Array.isArray(v.acceptedKeys)
        ? { ...v.acceptedKeys }
        : {},
    acceptedNotaries: Array.isArray(v.acceptedNotaries) ? v.acceptedNotaries.map(String) : [],
    evidenceMaxAgeMs: Math.max(1000, Number(v.evidenceMaxAgeMs) || 60000),
  };
}

export const now = () => Date.now();
export const newId = (prefix = 'a') =>
  `${prefix}_${now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
