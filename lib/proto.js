// Shared protocol constants + helpers for the agent cloud.
// Zero dependencies — used by the control plane, node-host, and CLI.

export const PROTO_VERSION = 1;

// Agent lifecycle states (control-plane authoritative).
export const STATE = {
  PENDING: 'pending', // created, not yet scheduled
  SCHEDULED: 'scheduled', // assigned to a node, not yet confirmed running
  RUNNING: 'running', // node confirms it's up
  STOPPING: 'stopping', // drain requested
  STOPPED: 'stopped', // not running (by request)
  FAILED: 'failed', // crashed / node lost
};

// Custody tiers, ordered weakest→strongest protection of the signing key.
// An agent requires a MINIMUM tier; a node OFFERS up to custodyMax.
export const CUSTODY = { KEY_ON_NODE: 0, ALLOWANCE: 1, OFFBOX: 2, TEE: 3 };
export const CUSTODY_NAME = ['key-on-node', 'allowance', 'offbox', 'tee'];
export const custodyRank = (name) => (name in CUSTODY ? CUSTODY[name] : CUSTODY[name?.toUpperCase?.()] ?? 0);

// A node can host an agent if it offers at least the protection the agent requires.
export function nodeSatisfies(node, agent) {
  const need = agentCustody(agent);
  const offer = node.custodyMax ?? CUSTODY.TEE; // default: accepts anything
  if (offer < need) return false;
  if (agent.spec?.confidential === 'required' && !node.caps?.tee) return false;
  return true;
}

export function agentCustody(agent) {
  const t = agent.custodyTier;
  if (typeof t === 'number') return t;
  return CUSTODY[String(t || 'KEY_ON_NODE').toUpperCase().replace(/-/g, '_')] ?? 0;
}

export const now = () => Date.now();
export const newId = (prefix = 'a') =>
  `${prefix}_${now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
