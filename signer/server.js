#!/usr/bin/env node
// Circuit Agent Cloud — Signer.
//
// The ONE custody mechanism. An agent's signing key is generated and held HERE,
// off-box, and never reaches the operator node that runs the agent's brain. The
// agent (running on someone else's CPU) sends a signed *intent* — "buy ≤X SOL of
// token T"; the signer checks it against the owner's policy and signs the trade.
//
// What this buys, in one service:
//   1. CUSTODY — the operator/host can never steal funds: the key isn't on their box,
//      and the AUTONOMOUS path is buy/sell-only (no transfer/withdraw), so the worst a
//      malicious host or a leaked session token can do is an *in-policy swap*. The OWNER
//      gets funds back two ways, both owner-gated (not the autonomous path): `withdraw`
//      sends SOL to the agent's committed owner address ONLY (never arbitrary), and
//      `export` hands the owner the wallet's private key to take full custody. NOTE: in
//      v1 these are gated by the operator bearer — a true multi-tenant deployment must add
//      per-owner auth, since the signer is otherwise a custodian of the agent wallets.
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
import { newKeypair, fromSeed, sign, seal, open, sha256hex, randomToken, base58, base58decode } from '../lib/ed25519.js';
import { normalizePolicy, normalizeVerified } from '../lib/proto.js';
import { decisionGate } from '../lib/verified-intent.js';
import { executeUltraSwap } from './submit.js';
import { withdrawSol, getBalanceLamports, hasTokenBalance } from './withdraw.js';

const PORT = Number(process.env.PORT || 18981);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.CIRCUIT_SIGNER_DIR || path.join(os.homedir(), '.circuit-signer');
const KEY = process.env.CIRCUIT_SIGNER_KEY || ''; // bearer for control-plane calls (open if unset)
// RPC for owner-recovery transfers (withdraw / safe-destroy balance checks). Swaps still go
// through Jupiter Ultra; this is only the System-transfer path back to the owner.
const RPC = process.env.CIRCUIT_SIGNER_RPC_URL || process.env.CIRCUIT_RPC_URL || 'https://api.mainnet-beta.solana.com';
const isPubkey = (s) => { try { return typeof s === 'string' && base58decode(s).length === 32; } catch { return false; } };
// Live trading lands swaps via Jupiter Ultra (it broadcasts, so the signer needs
// no RPC). lite-api is keyless+rate-limited; set JUPITER_ULTRA_API for the paid host.
const JUP_BASE = process.env.JUPITER_API_BASE || 'https://lite-api.jup.ag';
const JUP_KEY = process.env.JUPITER_ULTRA_API || process.env.JUPITER_API_KEY || '';

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

// Replay guard for verified-intent evidence nonces (TTL-swept; bounded). A reused
// nonce means a host is replaying stale authenticated data to re-justify a trade.
const _vnonce = new Map();
const VERIFIED_NONCES = {
  has: (n) => _vnonce.has(n),
  add: (n) => {
    _vnonce.set(n, Date.now());
    if (_vnonce.size > 5000) for (const [k, t] of _vnonce) if (Date.now() - t > 300000) _vnonce.delete(k);
  },
};

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
    owner: a.owner || null,
    verified: a.verified
      ? { ruleId: a.verified.rule?.id ?? null, acceptedKeys: Object.keys(a.verified.acceptedKeys).length, requireVerifiedIntent: !!a.policy.requireVerifiedIntent }
      : null,
  };
}

// ── Routes ────────────────────────────────────────────────────────────────────
const r = new Router();

r.get('/health', () => ({ ok: true, service: 'circuit-signer', agents: Object.keys(agents).length }));

// Provision (or fetch) an agent wallet + policy. Idempotent: the wallet is
// generated once and never regenerated, so an agent's address is stable.
r.post('/v1/agents', (ctx) => {
  auth(ctx);
  const { agentId, policy, verified, owner } = ctx.body;
  if (!agentId) fail(400, 'bad-request', 'agentId required');
  // The owner address is where funds can be withdrawn back to (the ONLY withdraw
  // destination — never arbitrary). Optional at create, settable later via the owner route.
  if (owner != null && !isPubkey(owner)) fail(400, 'bad-owner', 'owner must be a base58 pubkey');
  let a = agents[agentId];
  if (!a) {
    const kp = newKeypair();
    keys[agentId] = seal(MASTER, kp.seed);
    kp.seed.fill(0);
    a = agents[agentId] = {
      id: agentId,
      address: kp.address,
      owner: owner || null,
      policy: normalizePolicy(policy),
      verified: normalizeVerified(verified),
      day: utcDay(),
      daySpentSol: 0,
      lastTradeTs: 0,
      session: null,
      createdAt: Date.now(),
    };
    log(`provisioned ${agentId} -> ${kp.address}${owner ? ` (owner ${owner})` : ''}`);
  } else {
    if (policy) a.policy = normalizePolicy(policy);
    if (verified) a.verified = normalizeVerified(verified);
    if (owner) a.owner = owner;
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
  if (ctx.body.verified) a.verified = normalizeVerified(ctx.body.verified);
  persist();
  return publicView(a);
});

// Set/replace the owner withdraw address (the only destination withdrawals can reach).
r.put('/v1/agents/:id/owner', (ctx) => {
  auth(ctx);
  const a = agents[ctx.params.id];
  if (!a) fail(404, 'no-agent', 'no such agent');
  if (!isPubkey(ctx.body.owner)) fail(400, 'bad-owner', 'owner must be a base58 pubkey');
  a.owner = ctx.body.owner;
  persist();
  log(`owner set ${a.id} -> ${a.owner}`);
  return publicView(a);
});

// OWNER WITHDRAW (docs: SECURITY.md). Send the agent wallet's SOL back to the committed
// owner address — and ONLY that address. This is the owner's escape hatch; the autonomous
// path stays buy/sell-only. body: { amountSol? } (omit → full sweep minus fee). Bearer-gated
// (operator); a multi-tenant deployment must add per-owner auth in front of this.
r.post('/v1/agents/:id/withdraw', async (ctx) => {
  auth(ctx);
  const a = agents[ctx.params.id];
  if (!a) fail(404, 'no-agent', 'no such agent');
  if (!a.owner) fail(409, 'no-owner', 'no owner address on file — set one before withdrawing');
  const lamports = ctx.body.amountSol != null ? Math.round(Number(ctx.body.amountSol) * 1e9) : null;
  if (lamports != null && !(lamports > 0)) fail(400, 'bad-amount', 'amountSol must be > 0');
  const seed = open(MASTER, keys[a.id]);
  try {
    const r2 = await withdrawSol({ url: RPC, seed, fromB58: a.address, ownerB58: a.owner, lamports });
    log(`WITHDRAW ${a.id} ${(Number(r2.lamports) / 1e9).toFixed(6)} SOL -> owner ${a.owner} (${r2.signature})`);
    return { ok: true, code: 'withdrawn', signature: r2.signature, owner: a.owner, lamports: r2.lamports, remaining: r2.remaining };
  } catch (e) {
    fail(e.status || 502, e.code || 'withdraw-failed', `withdraw failed: ${e.message}`);
  } finally {
    seed.fill(0);
  }
});

// OWNER KEY EXPORT. Returns the agent wallet's secret key so the owner can take full
// custody (import into any wallet). This INTENTIONALLY hands out the key — after export the
// off-box "can't be stolen" property no longer holds for this wallet, so it's a deliberate
// owner action behind the operator bearer. The agent should be stopped first.
r.post('/v1/agents/:id/export', (ctx) => {
  auth(ctx);
  const a = agents[ctx.params.id];
  if (!a) fail(404, 'no-agent', 'no such agent');
  const seed = open(MASTER, keys[a.id]);
  try {
    const { pubkey } = fromSeed(seed);
    const secretKey = Buffer.concat([Buffer.from(seed), pubkey]); // 64-byte Solana secret key
    log(`EXPORTED key for ${a.id} (${a.address}) — owner took custody`);
    return { ok: true, address: a.address, seedHex: Buffer.from(seed).toString('hex'), secretKeyBase58: base58(secretKey) };
  } finally {
    seed.fill(0);
  }
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
r.post('/v1/agents/:id/intent', async (ctx) => {
  const a = agents[ctx.params.id];
  if (!a) fail(404, 'no-agent', 'no such agent');
  const { epoch, token, intent = {} } = ctx.body;

  // 1. The fence: only the holder of the current session may trade.
  if (!a.session) fail(403, 'fenced', 'no active session');
  if (epoch !== a.session.epoch || sha256hex(String(token || '')) !== a.session.tokenHash)
    fail(403, 'fenced', 'stale or invalid session — another instance holds the lease');

  // 1b. Verified-intent gate (docs/VERIFIED_INTENTS.md). The fence proves WHO is asking;
  // it can't prove the trade is honest, because the agent runs on the host's CPU and the
  // host could pick any in-policy buy/sell. So when the owner has committed a decision
  // rule, the signer re-derives the trade here: it accepts only if the rule, run on
  // AUTHENTICATED inputs (signed quotes / inference receipts / zkTLS), produces this exact
  // intent. A forged or unjustified trade is rejected before any signing. Opt-in: agents
  // without requireVerifiedIntent are unaffected (deterrence/TEE handle opaque strategies).
  if (a.policy.requireVerifiedIntent) {
    if (!a.verified?.rule) fail(409, 'no-rule', 'requireVerifiedIntent set but no committed rule');
    const g = decisionGate(
      { intent, rule: ctx.body.rule, inputs: ctx.body.inputs || {}, evidence: ctx.body.evidence || [] },
      {
        rule: a.verified.rule,
        acceptedKeys: a.verified.acceptedKeys,
        acceptedNotaries: a.verified.acceptedNotaries,
        maxAgeMs: a.verified.evidenceMaxAgeMs,
        replay: VERIFIED_NONCES,
      },
    );
    if (!g.ok) fail(403, g.code, `verified-intent rejected: ${g.code}`);
  }

  // 2. Policy. Only buy|sell exist — there is no transfer/withdraw verb.
  const kind = intent.kind;
  if (!['buy', 'sell'].includes(kind)) fail(400, 'bad-intent', 'kind must be buy|sell');
  if (!a.policy.allow.includes(kind)) fail(403, 'action-not-allowed', `${kind} not allowed by policy`);
  if (intent.token && a.policy.denyTokens.includes(intent.token)) fail(403, 'token-denied', 'token denied by policy');
  if (intent.token && a.policy.allowTokens && !a.policy.allowTokens.includes(intent.token)) fail(403, 'token-not-allowed', 'token not in allowlist');
  const sinceLast = Date.now() - (a.lastTradeTs || 0);
  if (sinceLast < a.policy.cooldownMs) fail(429, 'cooldown', `cooldown ${a.policy.cooldownMs - sinceLast}ms remaining`);
  if (a.day !== utcDay()) { a.day = utcDay(); a.daySpentSol = 0; }

  // Notional is SOL-denominated. For a BUY it's exactly sizeSol (SOL in) and is
  // capped up front. For a live SELL the SOL value is the swap OUTPUT — known only
  // from the order — so it's enforced inside executeUltraSwap against order.outAmount
  // (sizeSol can't bound it). In paper, sizeSol is the declared notional for both.
  const sizeSol = Number(intent.sizeSol);
  const liveSell = kind === 'sell' && !a.policy.paper;
  if (!liveSell) {
    if (!(sizeSol > 0)) fail(400, 'bad-intent', 'sizeSol must be > 0');
    if (sizeSol > a.policy.maxNotionalSol) fail(403, 'over-trade-cap', `size ${sizeSol} > maxNotionalSol ${a.policy.maxNotionalSol}`);
    if (a.daySpentSol + sizeSol > a.policy.maxDailySol) fail(403, 'over-daily-cap', `daily ${a.daySpentSol.toFixed(4)}+${sizeSol} > ${a.policy.maxDailySol}`);
  } else if (!(Number(intent.amount) > 0)) {
    fail(400, 'bad-intent', 'live sell needs intent.amount in token base units');
  }

  // 3. Sign. The seed is decrypted only for as long as it takes to sign, then wiped.
  const seed = open(MASTER, keys[a.id]);
  const kp = fromSeed(seed);
  const ts = Date.now();
  const canonical = JSON.stringify({ agentId: a.id, epoch, kind, token: intent.token || null, sizeSol: sizeSol || null, ts });
  const attest = sign(kp.priv, canonical).toString('base64');

  // 4a. PAPER — sign the intent attestation, account, done (no broadcast).
  if (a.policy.paper) {
    seed.fill(0); kp.seed.fill(0);
    a.daySpentSol += sizeSol; a.lastTradeTs = ts;
    persist();
    log(`signed ${a.id} ${kind} ${sizeSol} SOL ${intent.token || ''} (epoch ${epoch}, paper)`);
    return { ok: true, code: 'signed', address: kp.address, signature: attest, paper: true, submitted: false, attestation: { canonical }, daySpentSol: +a.daySpentSol.toFixed(6) };
  }

  // 4b. LIVE — build + validate + land the swap via Ultra. The caps are enforced
  // on the swap's real SOL value (also inside executeUltraSwap, so a live SELL
  // can't escape them), and we charge the daily budget by that actual value.
  const remainingDailySol = Math.max(0, a.policy.maxDailySol - a.daySpentSol);
  try {
    const r = await executeUltraSwap({
      seed, address: kp.address,
      intent: { kind, token: intent.token, sizeSol, amount: intent.amount, maxSlippageBps: intent.maxSlippageBps },
      apiBase: JUP_BASE, apiKey: JUP_KEY,
      maxNotionalSol: a.policy.maxNotionalSol, remainingDailySol,
    });
    seed.fill(0); kp.seed.fill(0);
    a.daySpentSol += r.solValue; a.lastTradeTs = ts;
    persist();
    log(`SUBMITTED ${a.id} ${kind} ${r.solValue.toFixed(4)} SOL ${intent.token} -> ${r.txid} (${r.status}${r.altPrograms ? `, ${r.altPrograms} ALT-program(s) unverified` : ''})`);
    return { ok: true, code: 'submitted', address: kp.address, signature: attest, paper: false, submitted: true, txid: r.txid, status: r.status, solValue: +r.solValue.toFixed(6), attestation: { canonical }, daySpentSol: +a.daySpentSol.toFixed(6) };
  } catch (e) {
    seed.fill(0); kp.seed.fill(0); // no accounting advance on failure
    fail(e.status || 502, e.code || 'submit-failed', `live submit failed: ${e.message}`);
  }
});

// Destroy wipes the wallet key — which is IRREVERSIBLE: any funds left in the wallet become
// permanently unrecoverable. So we fail closed on a non-empty wallet (SOL above the fee
// reserve, or any token balance) and tell the caller to withdraw/export first. `force:true`
// overrides for a knowingly-empty wallet or an accepted loss. RPC-unreachable also fails
// closed (we can't prove it's empty) unless forced.
r.delete('/v1/agents/:id', async (ctx) => {
  auth(ctx);
  const a = agents[ctx.params.id];
  if (!a) fail(404, 'no-agent', 'no such agent');
  const force = ctx.body?.force === true || ctx.query?.force === '1';
  if (!force) {
    let bal, tokens;
    try {
      bal = await getBalanceLamports(RPC, a.address);
      tokens = await hasTokenBalance(RPC, a.address);
    } catch (e) {
      fail(503, 'balance-unreadable', `cannot verify the wallet is empty (${e.message}) — withdraw/export then retry, or use force`);
    }
    if (bal > 10000n || tokens)
      fail(409, 'not-empty', `wallet still holds ${(Number(bal) / 1e9).toFixed(6)} SOL${tokens ? ' + token balance' : ''} — withdraw or export first (or force to abandon it)`);
  }
  delete agents[ctx.params.id];
  delete keys[ctx.params.id];
  persist();
  log(`destroyed ${ctx.params.id} (wallet key wiped${force ? ', forced' : ', verified empty'})`);
  return { ok: true };
});

r.listen(PORT, HOST, () => log(`signer on http://${HOST}:${PORT}  data=${DATA_DIR}  auth=${KEY ? 'on' : 'open'}  agents=${Object.keys(agents).length}`));
