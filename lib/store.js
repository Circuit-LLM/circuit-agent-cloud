// In-memory state with atomic JSON persistence. Good enough for the v1 control
// plane; swap for Postgres when multi-instance HA is needed (see SPEC §13).
import fs from 'node:fs';
import path from 'node:path';

const LOG_RING = 500; // per-agent log lines kept

export class Store {
  constructor(file) {
    this.file = file;
    this.nodes = new Map();
    this.agents = new Map();
    this.logs = new Map(); // agentId -> [{ts, line}]
    this._load();
  }

  _load() {
    try {
      const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      for (const n of raw.nodes || []) this.nodes.set(n.nodeId, n);
      for (const a of raw.agents || []) this.agents.set(a.id, a);
      // logs are ephemeral; not persisted
    } catch {
      /* fresh */
    }
  }

  persist() {
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      const tmp = this.file + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify({ nodes: [...this.nodes.values()], agents: [...this.agents.values()] }));
      fs.renameSync(tmp, this.file);
    } catch {
      /* best-effort */
    }
  }

  // ── nodes ──
  upsertNode(node) {
    this.nodes.set(node.nodeId, { ...this.nodes.get(node.nodeId), ...node });
    return this.nodes.get(node.nodeId);
  }
  getNode(id) { return this.nodes.get(id); }
  listNodes() { return [...this.nodes.values()]; }

  // ── agents ──
  putAgent(a) { this.agents.set(a.id, a); this.persist(); return a; }
  getAgent(id) { return this.agents.get(id); }
  updateAgent(id, patch) {
    const a = this.agents.get(id);
    if (!a) return null;
    Object.assign(a, patch);
    this.persist();
    return a;
  }
  deleteAgent(id) { this.agents.delete(id); this.logs.delete(id); this.persist(); }
  listAgents(filter) {
    const all = [...this.agents.values()];
    return filter ? all.filter(filter) : all;
  }

  // ── logs ──
  appendLogs(agentId, lines) {
    if (!this.logs.has(agentId)) this.logs.set(agentId, []);
    const buf = this.logs.get(agentId);
    for (const l of lines) buf.push(l);
    if (buf.length > LOG_RING) buf.splice(0, buf.length - LOG_RING);
  }
  getLogs(agentId, since = 0) {
    return (this.logs.get(agentId) || []).filter((l) => l.ts > since);
  }
}
