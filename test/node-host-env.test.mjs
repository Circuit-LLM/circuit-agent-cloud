// B0 — the curated-env hotfix: a hosted workload gets an explicit allowlist, never the operator's
// whole environment. Proves the leak is closed AND that the trust distinction (built-in vs bundle)
// holds: built-ins keep their first-party secrets; a bundle never receives a secret.
import assert from 'node:assert';
import { buildAgentEnv, SECRET_ENV } from '../node-host/env.js';

// A realistic operator environment: legitimate Circuit config + UNRELATED operator secrets that
// must never reach a hosted agent.
const srcEnv = {
  PATH: '/usr/bin',
  AGENT_KEYPAIR: 'first-party-trading-key',
  JUPITER_API_KEY: 'jup-key',
  CIRCUIT_INTERNAL_KEY: 'internal-bypass',
  CIRCUIT_RPC_URL: 'https://rpc.example/?api-key=xyz',
  GATEWAY_URL: 'https://gateway.example',
  OPERATOR_SSH_KEY: 'LEAK-ME',           // unrelated — must NOT pass through
  AWS_SECRET_ACCESS_KEY: 'LEAK-ME-TOO',  // unrelated — must NOT pass through
  CIRCUIT_CLOUD_KEY: 'the-node-host-own-key', // the host's own auth key — must NOT pass through
};

const signer = { url: 'http://signer', agentId: 'a1', epoch: 3, token: 'sess-tok', address: 'Addr11', paper: true };

// ── trusted built-in workload (agentd / circuit-agent) ──────────────────────────────
{
  const env = buildAgentEnv({ name: 'bot', spec: { workload: 'circuit-agent' }, signer }, '/data/bot', srcEnv);

  // identity + session present (off-box custody: the token, never a key)
  assert.equal(env.CIRCUIT_AGENT_SESSION, 'sess-tok', 'session token forwarded');
  assert.equal(env.CIRCUIT_SIGNER_URL, 'http://signer');
  assert.equal(env.CIRCUIT_AGENT_PAPER, '1', 'paper flag set');
  assert.equal(env.CIRCUIT_AGENT_DATA_DIR, '/data/bot');
  assert.equal(env.HOME, '/data/bot', 'HOME confined to the agent data dir');
  assert.equal(env.TMPDIR, '/data/bot/tmp', 'TMPDIR confined to the agent data dir');

  // trusted built-ins keep the first-party secrets + endpoints they actually read
  assert.equal(env.AGENT_KEYPAIR, 'first-party-trading-key', 'trusted built-in gets its first-party secret');
  assert.equal(env.JUPITER_API_KEY, 'jup-key');
  assert.equal(env.CIRCUIT_RPC_URL, 'https://rpc.example/?api-key=xyz', 'endpoint forwarded');
  assert.equal(env.GATEWAY_URL, 'https://gateway.example');

  // the leak is closed: nothing unrelated, and not the host's own key
  assert.equal(env.OPERATOR_SSH_KEY, undefined, 'unrelated operator secret NOT leaked');
  assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined, 'unrelated operator secret NOT leaked');
  assert.equal(env.CIRCUIT_CLOUD_KEY, undefined, "the node-host's own auth key NOT leaked");
}

// ── untrusted bundle (B1+) ──────────────────────────────────────────────────────────
{
  const env = buildAgentEnv(
    { name: 'userbot', spec: { bundle: { sha256: 'abc' }, env: { AGENT_KEYPAIR: 'evil-smuggle', CIRCUIT_RPC_URL: 'evil', NODE_OPTIONS: '--require /data/evil.js', LD_PRELOAD: '/data/x.so', FOO: 'bar' } }, signer },
    '/data/userbot', srcEnv,
  );

  // a bundle still gets its own identity/session
  assert.equal(env.CIRCUIT_AGENT_SESSION, 'sess-tok', 'bundle gets its session token');
  assert.equal(env.CIRCUIT_AGENT_DATA_DIR, '/data/userbot');

  // …but NEVER a first-party secret — not from the operator env, not smuggled via spec.env
  for (const k of SECRET_ENV) assert.equal(env[k], undefined, `bundle must not receive secret ${k}`);
  assert.equal(env.AGENT_KEYPAIR, undefined, 'bundle cannot smuggle a secret-named var through spec.env');

  // the KEYED RPC URL is withheld from an untrusted bundle (D1) — not from the operator env, not smuggled
  assert.equal(env.CIRCUIT_RPC_URL, undefined, 'untrusted bundle does NOT get the keyed CIRCUIT_RPC_URL');
  // process-influencing vars are dropped (D2)
  assert.equal(env.NODE_OPTIONS, undefined, 'NODE_OPTIONS cannot be set via spec.env');
  assert.equal(env.LD_PRELOAD, undefined, 'LD_PRELOAD cannot be set via spec.env');
  // a safe (non-credentialed) endpoint is still reachable; benign declared env passes; no unrelated leak
  assert.equal(env.GATEWAY_URL, 'https://gateway.example');
  assert.equal(env.FOO, 'bar', 'benign spec.env var passes through');
  assert.equal(env.OPERATOR_SSH_KEY, undefined);
}

// ── untrusted bundle gets a substituted keyless RPC when the operator provides one ───
{
  const env = buildAgentEnv(
    { name: 'ub2', spec: { bundle: { sha256: 'abc' } }, signer },
    '/data/ub2', { ...srcEnv, CIRCUIT_PUBLIC_RPC_URL: 'https://public-rpc.example' },
  );
  assert.equal(env.CIRCUIT_RPC_URL, 'https://public-rpc.example', 'keyless public RPC substituted for untrusted');
}

// ── spec.env can't shadow protected identity vars ────────────────────────────────────
{
  const env = buildAgentEnv(
    { name: 'x', spec: { workload: 'agentd', env: { CIRCUIT_AGENT_SESSION: 'forged', CIRCUIT_SIGNER_URL: 'http://evil' } }, signer },
    '/data/x', srcEnv,
  );
  assert.equal(env.CIRCUIT_AGENT_SESSION, 'sess-tok', 'spec.env cannot overwrite the real session');
  assert.equal(env.CIRCUIT_SIGNER_URL, 'http://signer', 'spec.env cannot overwrite the signer URL');
}

console.log('node-host env (B0): all assertions passed');
