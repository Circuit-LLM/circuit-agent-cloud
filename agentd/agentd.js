#!/usr/bin/env node
// Reference Circuit agent workload — a self-contained paper trader.
//
// The cloud runs *workloads*; this is the simplest real one (no external
// services, safe to run anywhere). circuit-agent is the production workload —
// the node-host launches it the same way, just with a different command.
//
// Contract (how the node-host drives any workload):
//   env CIRCUIT_AGENT_DATA_DIR  — where to read config + write state/logs
//   env AGENT_NAME              — display name
//   writes  <dataDir>/heartbeat.json   {ts, state, uptimeS, scans, pnlPct, positions}
//   writes  <dataDir>/agent.log        append-only log (the node-host tails this)
//   SIGTERM/SIGINT → checkpoint + exit(0)
import fs from 'node:fs';
import path from 'node:path';

const DATA_DIR = process.env.CIRCUIT_AGENT_DATA_DIR || process.cwd();
const NAME = process.env.AGENT_NAME || 'agent';
const LOG_FILE = path.join(DATA_DIR, 'agent.log');
const HB_FILE = path.join(DATA_DIR, 'heartbeat.json');

// Off-box custody, handed in by the node-host (never the key — just a scoped,
// rotating session token for this agent + epoch). When set, every entry is
// authorized and signed by the signer; when absent, we run pure-paper locally.
const SIGNER = process.env.CIRCUIT_SIGNER_URL || '';
const AGENT_ID = process.env.CIRCUIT_AGENT_ID || '';
const EPOCH = Number(process.env.CIRCUIT_AGENT_EPOCH || 0);
const SESSION = process.env.CIRCUIT_AGENT_SESSION || '';
const ADDRESS = process.env.CIRCUIT_AGENT_ADDRESS || '';

let cfg = { scanIntervalMs: 5000, paperTrading: true, strategy: 'dip-reversal', tradeSizeSol: 0.01 };
try {
  cfg = { ...cfg, ...JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'config.json'), 'utf8')) };
} catch {
  /* defaults */
}

// Ask the signer to authorize + sign a trade. The reply is either a signature
// (custody confirmed it against policy + the fence) or a rejection code.
async function signTrade(kind, token, sizeSol) {
  if (!SIGNER) return { ok: true, code: 'paper-local', signature: null };
  try {
    const res = await fetch(`${SIGNER}/v1/agents/${AGENT_ID}/intent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ epoch: EPOCH, token: SESSION, intent: { kind, token, sizeSol } }),
      signal: AbortSignal.timeout(6000),
    });
    const j = await res.json().catch(() => ({}));
    return res.ok ? j : { ok: false, code: j.code || `http-${res.status}`, error: j.error };
  } catch (e) {
    return { ok: false, code: 'signer-unreachable', error: e.message };
  }
}

const started = Date.now();
let scans = 0;
let pnlPct = 0;
let positions = [];
let running = true;
let signedTrades = 0;

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  try {
    fs.appendFileSync(LOG_FILE, line);
  } catch {}
  process.stdout.write(line);
}

function heartbeat(state) {
  const hb = {
    ts: Date.now(),
    state,
    name: NAME,
    uptimeS: Math.round((Date.now() - started) / 1000),
    scans,
    pnlPct: +pnlPct.toFixed(2),
    positions,
    paper: cfg.paperTrading !== false,
    custody: SIGNER ? 'offbox-signer' : 'local',
    address: ADDRESS || undefined,
    signedTrades,
  };
  try {
    fs.writeFileSync(HB_FILE, JSON.stringify(hb));
  } catch {}
}

let busy = false;
async function tick() {
  if (!running || busy) return;
  busy = true;
  try {
    scans++;
    // Toy strategy: occasionally enter/exit. Every ENTRY is routed through the
    // signer — the agent has no key, so it can only trade if custody signs off.
    const r = Math.random();
    if (positions.length === 0 && r < 0.3) {
      const token = `TKN${scans}`;
      const size = cfg.tradeSizeSol ?? 0.01;
      const sig = await signTrade('buy', token, size);
      if (sig.ok) {
        signedTrades++;
        positions.push({ symbol: token, entryPnl: 0, sizeSol: size });
        const tag = sig.signature ? `sig ${sig.signature.slice(0, 16)}…` : '(paper-local)';
        log(`scan #${scans} — BUY ${token} ${size} SOL ✓ signed off-box ${tag}`);
      } else {
        log(`scan #${scans} — BUY ${token} DENIED by signer [${sig.code}] ${sig.error || ''}`);
      }
    } else if (positions.length && r < 0.4) {
      const p = positions.pop();
      const realized = (Math.random() - 0.45) * 4;
      pnlPct += realized;
      log(`scan #${scans} — closed ${p.symbol} ${realized >= 0 ? '+' : ''}${realized.toFixed(2)}% (total ${pnlPct.toFixed(2)}%)`);
    } else {
      log(`scan #${scans} — no setup (holding ${positions.length})`);
    }
    heartbeat('running');
  } finally {
    busy = false;
  }
}

function shutdown(sig) {
  running = false;
  log(`${sig} — checkpointing and exiting`);
  heartbeat('stopped');
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

fs.mkdirSync(DATA_DIR, { recursive: true });
log(`agentd up — name=${NAME} strategy=${cfg.strategy} paper=${cfg.paperTrading !== false} interval=${cfg.scanIntervalMs}ms`);
log(SIGNER
  ? `custody=offbox-signer wallet=${ADDRESS || '?'} epoch=${EPOCH} — no signing key on this host`
  : `custody=local — no signer wired (pure paper)`);
heartbeat('running');
setInterval(tick, cfg.scanIntervalMs);
