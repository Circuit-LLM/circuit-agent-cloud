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

let cfg = { scanIntervalMs: 5000, paperTrading: true, strategy: 'dip-reversal' };
try {
  cfg = { ...cfg, ...JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'config.json'), 'utf8')) };
} catch {
  /* defaults */
}

const started = Date.now();
let scans = 0;
let pnlPct = 0;
let positions = [];
let running = true;

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
  };
  try {
    fs.writeFileSync(HB_FILE, JSON.stringify(hb));
  } catch {}
}

function tick() {
  if (!running) return;
  scans++;
  // Toy paper strategy: occasionally open/close a position, walk P&L a touch.
  const r = Math.random();
  if (positions.length === 0 && r < 0.3) {
    positions.push({ symbol: `TKN${scans}`, entryPnl: 0 });
    log(`scan #${scans} — opened paper position ${positions[0].symbol}`);
  } else if (positions.length && r < 0.4) {
    const p = positions.pop();
    const realized = (Math.random() - 0.45) * 4;
    pnlPct += realized;
    log(`scan #${scans} — closed ${p.symbol} ${realized >= 0 ? '+' : ''}${realized.toFixed(2)}% (total ${pnlPct.toFixed(2)}%)`);
  } else {
    log(`scan #${scans} — no setup (holding ${positions.length})`);
  }
  heartbeat('running');
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
heartbeat('running');
setInterval(tick, cfg.scanIntervalMs);
