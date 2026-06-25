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
// signer (see signer/server.js), never on the operator node. So any live node can
// host any agent — the scheduler only weighs capacity, not trust. This hook stays
// for future capability matching (e.g. region/cap pinning) and is open by default.
export function nodeSatisfies(_node, _agent) {
  return true;
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
  return n;
}

export const now = () => Date.now();
export const newId = (prefix = 'a') =>
  `${prefix}_${now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
