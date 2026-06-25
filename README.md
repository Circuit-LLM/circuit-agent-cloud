<div align="center">

# circuit-agent-cloud

**Decentralized CPU hosting for Circuit agents. Users launch agents that run 24/7 on the mesh; operators contribute spare CPU on their own terms and earn CIRC. Inference runs on the GPUs — agents run on the CPUs that hang off the same node-clients.**

[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)
[![Status](https://img.shields.io/badge/status-alpha-orange)](https://github.com/Circuit-LLM/circuit-agent-cloud)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](LICENSE)

[Website](https://circuitllm.xyz) · [Spec](https://github.com/Circuit-LLM/circuit-cli/blob/main/docs/agent-cloud-spec.md)

</div>

---

Three zero-dependency Node services that together form the agent cloud:

| Component | What it is |
| --------- | ---------- |
| **control-plane** | Scheduler + registry + log relay. Nodes poll it; the CLI drives agents through it. The only inbound service. |
| **node-host** | The operator's worker. Declares a resource budget, runs assigned agents (sandboxed, bounded), forwards health + logs. Polls out only — no inbound port. |
| **agentd** | A reference agent workload (self-contained paper trader). Production runs `circuit-agent` the same way — it's just another workload command. |

Driven from the terminal by **[circuit-cli](https://github.com/Circuit-LLM/circuit-cli)** (`circuit agent …`). Full design in the **[spec](https://github.com/Circuit-LLM/circuit-cli/blob/main/docs/agent-cloud-spec.md)**.

## How it works

```
┌── user ──┐  HTTPS   ┌──── control-plane ────┐  poll   ┌── operator ──┐
│ circuit  │ ───────► │ schedule · registry   │ ◄────── │  node-host   │
│  agent   │          │ · log relay · failover │         │ runs agentd/ │
└──────────┘          └────────────────────────┘         │ circuit-agent│
                                                          └──────────────┘
```

A node registers with a **budget**; the control plane bin-packs agents onto nodes that fit; nodes heartbeat and get `start`/`stop` assignments; agents' positions live on-chain so a crashed node's agents **reschedule and resume** elsewhere with nothing lost.

## Run it

No dependencies — pure Node ≥ 18.

**Control plane** (one per network):

```bash
PORT=18980 node control-plane/server.js
# env: HOST, NODE_TIMEOUT_MS, CIRCUIT_CLOUD_KEY (shared bearer), CIRCUIT_CLOUD_STATE
```

**Node host** (each operator — opt-in, bounded, revocable):

```bash
CONTROL_PLANE=https://agents.circuitllm.xyz \
NODE_ID=my-node MAX_AGENTS=20 MAX_MEMORY_MB=512 CUSTODY_MAX=3 \
node node-host/host.js
```

Or, from the CLI: `circuit agent host --max-agents 20` (and `--off` to drain & stop).

### Operator budget

The opt-in controls — set via env or `circuit agent host` — are **off by default** and enforced with hard caps:

| Knob | Meaning |
| ---- | ------- |
| `MAX_AGENTS` | hard ceiling on hosted agents |
| `MAX_MEMORY_MB` | per-agent memory cap (best-effort kill on Linux; cgroups in prod) |
| `CUSTODY_MAX` | max custody risk accepted — `0` key-on-node … `3` TEE/any |
| `CONFIDENTIAL_TEE=1` | advertise a TEE-capable host |
| `CONTROL_PLANE` | which network to join |

Lowering the budget or stopping the host **drains** its agents — they reschedule elsewhere.

## Status & roadmap

Alpha. The control plane, node-host, reference workload, scheduling, health/log relay and **crash failover** are working and end-to-end tested. Per the [spec](https://github.com/Circuit-LLM/circuit-cli/blob/main/docs/agent-cloud-spec.md), next up: custody tiers (Allowance / off-box-MPC / TEE), the CIRC hosting toll through the live distributor, cgroup/container sandboxing, and a Postgres store for HA.

## License

MIT © Circuit LLM
