#!/usr/bin/env node
// Circuit Agent Cloud — Signer.
//
// The ONE custody mechanism. An agent's signing key is generated and held HERE,
// off-box, and never reaches the operator node that runs the agent's brain. The
// agent (running on someone else's CPU) sends a signed *intent* — "buy ≤X SOL of
// token T"; the signer checks it against the owner's policy and signs the trade.
//
// What this buys, in one service:
//   1. CUSTODY — the operator can never steal funds: the key isn't on their box.
//      The worst a malicious operator (or a leaked session token) can do is make
//      the agent place an *in-policy swap* — value stays inside the agent wallet.
//      There is no 'transfer'/'withdraw' verb here at all, so funds can't leave;
//      withdrawals are done by the owner with their own key, never autonomously.
//   2. THE FENCE (at-most-one) — each agent has ONE wallet, so at most one live
//      instance may trade it. A session carries a monotonic epoch + secret token;
//      opening a new session (on reschedule/failover) supersedes the old one, so
//      a crashed node's orphaned copy is fenced out — its intents are rejected.
//
// Keys are sealed at rest (AES-256-GCM) under a master key. v1 = one trusted
// signer (Circuit's, or self-hosted); the same API can later sit behind an MPC
// or TEE signer with no change to agents or hosts. Live on-chain submission is a
// single documented seam (search "LIVE SUBMIT SEAM").
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { Router } from '../lib/http.js';
import { newKeypair, fromSeed, sign, seal, open, sha256hex, randomToken } from '../lib/ed25519.js';
import { normalizePolicy } from '../lib/proto.js';

const PORT = Number(process.env.PORT || 18981);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.CIRCUIT_SIGNER_DIR || path.join(os.homedir(), '.circuit-signer');
const KEY = process.env.CIRCUIT_SIGNER_KEY || ''; // bearer for control-plane calls (open if unset)

const log = (...a) => console.log(`[${new Date().toISOString()}] [signer]`, ...a);

fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Master key (root of trust for at-rest key sealing) ────────────────────────
function loadMaster() {
  const env = process.env.CIRCUIT_SIGNER_MASTER_KEY;
  if (env) {
    const buf = /^[0-9a-f]{64}$/i.test(env) ? Buffer.from(env, 'hex') : Buffer.from(env, 'base64');
    if (buf.length !== 32) throw new Error('CIRCUIT_SIGNER_MASTER_KEY must be 32 bytes (hex or base64)');
    return buf;
  }
  const f = path.join(DATA_DIR, 'master.key');
  try {
    return fs.readFileSync(f);
  } catch {
    const k = crypto.randomBytes(32);
    fs.writeFileSync(f, k, { mode: 0o600 });
    log(`generated a new master key at ${f} (back this up — it unlocks every agent wallet)`);
    return k;
  }
}
const MASTER = loadMaster();

// ── Persistence (agents.json = policy + session meta; keys.json = sealed seeds) ─
const AGENTS_FILE = path.join(DATA_DIR, 'agents.json');
const KEYS_FILE = path.join(DATA_DIR, 'keys.json');
const load = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return {}; } };
const agents = load(AGENTS_FILE); // id -> { address, policy, day, daySpentSol, lastTradeTs, epoch, session, createdAt }
const keys = load(KEYS_FILE); // id -> sealed seed { iv, tag, ct }

let writing = false;
function persist() {
  if (writing) return;
  writing = true;
  queueMicrotask(() => {
    writing = false;
    try {
      fs.writeFileSync(AGENTS_FILE + '.tmp', JSON.stringify(agents)); fs.renameSync(AGENTS_FILE + '.tmp', AGENTS_FILE);
      fs.writeFileSync(KEYS_FILE + '.tmp', JSON.stringify(keys), { mode: 0o600 }); fs.renameSync(KEYS_FILE + '.tmp', KEYS_FILE);
    } catch (e) { log('persist failed:', e.message); }
  });
}

const utcDay = () => new Date().toISOString().slice(0, 10);
const fail = (status, code, error) => { const e = new Error(error); e.status = status; e.code = code; throw e; };

function auth(ctx) {
  if (!KEY) return;
  const got = (ctx.req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (got !== KEY) fail(401, 'unauthorized', 'unauthorized');
}

function publicView(a) {
  return {
    agentId: a.id,
    address: a.address,
    policy: a.policy,
    custody: 'offbox-signer',
    daySpentSol: a.day === utcDay() ? a.daySpentSol : 0,
    epoch: a.session?.epoch ?? 0,
    hasSession: !!a.session,
    lastTradeTs: a.lastTradeTs || 0,
  };
}

// ── Routes ────────────────────────────────────────────────────────────────────
const r = new Router();

r.get('/health', () => ({ ok: true, service: 'circuit-signer', agents: Object.keys(agents).length }));

// Provision (or fetch) an agent wallet + policy. Idempotent: the wallet is
// generated once and never regenerated, so an agent's address is stable.
r.post('/v1/agents', (ctx) => {
  auth(ctx);
  const { agentId, policy } = ctx.body;
  if (!agentId) fail(400, 'bad-request', 'agentId required');
  let a = agents[agentId];
  if (!a) {
    const kp = newKeypair();
    keys[agentId] = seal(MASTER, kp.seed);
    kp.seed.fill(0);
    a = agents[agentId] = {
      id: agentId,
      address: kp.address,
      policy: normalizePolicy(policy),
      day: utcDay(),
      daySpentSol: 0,
      lastTradeTs: 0,
      session: null,
      createdAt: Date.now(),
    };
    log(`provisioned ${agentId} -> ${kp.address}`);
  } else if (policy) {
    a.policy = normalizePolicy(policy);
  }
  persist();
  return publicView(a);
});

r.get('/v1/agents/:id', (ctx) => {
  auth(ctx);
  const a = agents[ctx.params.id];
  if (!a) fail(404, 'no-agent', 'no such agent');
  return publicView(a);
});

r.put('/v1/agents/:id/policy', (ctx) => {
  auth(ctx);
  const a = agents[ctx.params.id];
  if (!a) fail(404, 'no-agent', 'no such agent');
  a.policy = normalizePolicy(ctx.body.policy);
  persist();
  return publicView(a);
});

// Open (rotate) the agent's session — THE FENCE. Returns a fresh epoch + token;
// any prior session is immediately superseded. Called by the control plane on
// each placement, so a reschedule fences out the previous node's orphan.
r.post('/v1/agents/:id/session', (ctx) => {
  auth(ctx);
  const a = agents[ctx.params.id];
  if (!a) fail(404, 'no-agent', 'no such agent');
  const epoch = (a.session?.epoch ?? 0) + 1;
  const token = randomToken();
  a.session = { epoch, tokenHash: sha256hex(token), node: ctx.body.node || null, openedAt: Date.now() };
  persist();
  log(`session ${a.id} -> epoch ${epoch} (node ${a.session.node || '?'})`);
  return { agentId: a.id, address: a.address, epoch, token, paper: a.policy.paper };
});

// Authorize + sign a trade intent. Auth is the session token itself (scoped to
// one agent + epoch) — the caller never needs the master/bearer key.
r.post('/v1/agents/:id/intent', (ctx) => {
  const a = agents[ctx.params.id];
  if (!a) fail(404, 'no-agent', 'no such agent');
  const { epoch, token, intent = {} } = ctx.body;

  // 1. The fence: only the holder of the current session may trade.
  if (!a.session) fail(403, 'fenced', 'no active session');
  if (epoch !== a.session.epoch || sha256hex(String(token || '')) !== a.session.tokenHash)
    fail(403, 'fenced', 'stale or invalid session — another instance holds the lease');

  // 2. Policy. NB: only buy|sell exist — funds can never leave the wallet here.
  const kind = intent.kind;
  if (!['buy', 'sell'].includes(kind)) fail(400, 'bad-intent', 'kind must be buy|sell');
  if (!a.policy.allow.includes(kind)) fail(403, 'action-not-allowed', `${kind} not allowed by policy`);
  const size = Number(intent.sizeSol);
  if (!(size > 0)) fail(400, 'bad-intent', 'sizeSol must be > 0');
  if (size > a.policy.maxNotionalSol) fail(403, 'over-trade-cap', `size ${size} > maxNotionalSol ${a.policy.maxNotionalSol}`);
  if (intent.token && a.policy.denyTokens.includes(intent.token)) fail(403, 'token-denied', 'token denied by policy');
  if (intent.token && a.policy.allowTokens && !a.policy.allowTokens.includes(intent.token)) fail(403, 'token-not-allowed', 'token not in allowlist');
  if (a.day !== utcDay()) { a.day = utcDay(); a.daySpentSol = 0; }
  if (a.daySpentSol + size > a.policy.maxDailySol) fail(403, 'over-daily-cap', `daily ${a.daySpentSol.toFixed(4)}+${size} > ${a.policy.maxDailySol}`);
  const sinceLast = Date.now() - (a.lastTradeTs || 0);
  if (sinceLast < a.policy.cooldownMs) fail(429, 'cooldown', `cooldown ${a.policy.cooldownMs - sinceLast}ms remaining`);

  // 3. Sign. The seed is decrypted only for the moment it takes to sign, then wiped.
  const seed = open(MASTER, keys[a.id]);
  const kp = fromSeed(seed);
  const ts = Date.now();
  const canonical = JSON.stringify({ agentId: a.id, epoch, kind, token: intent.token || null, sizeSol: size, ts });
  const signature = sign(kp.priv, canonical).toString('base64');
  seed.fill(0); kp.seed.fill(0);

  // 4. Account + (paper) record. LIVE SUBMIT SEAM: when policy.paper === false,
  // build the Jupiter swap tx from `intent`, sign with `kp` (seed‖pubkey is a
  // Solana secret key) and broadcast via the RPC here, returning the real txid.
  a.daySpentSol += size; a.lastTradeTs = ts;
  persist();
  log(`signed ${a.id} ${kind} ${size} SOL ${intent.token || ''} (epoch ${epoch}, paper=${a.policy.paper})`);
  return {
    ok: true, code: 'signed', address: kp.address, signature, paper: a.policy.paper, submitted: false,
    attestation: { canonical }, daySpentSol: +a.daySpentSol.toFixed(6),
  };
});

r.delete('/v1/agents/:id', (ctx) => {
  auth(ctx);
  const a = agents[ctx.params.id];
  if (!a) fail(404, 'no-agent', 'no such agent');
  delete agents[ctx.params.id];
  delete keys[ctx.params.id];
  persist();
  log(`destroyed ${ctx.params.id} (wallet key wiped)`);
  return { ok: true };
});

r.listen(PORT, HOST, () => log(`signer on http://${HOST}:${PORT}  data=${DATA_DIR}  auth=${KEY ? 'on' : 'open'}  agents=${Object.keys(agents).length}`));
