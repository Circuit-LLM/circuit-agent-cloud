# Remote worker pod — move the muscle off the VPS

**Goal:** run the *workers* (the 6 circuit-node clients + the agent-cloud node-host that hosts user
agents) on a dedicated CPU pod (e.g. RunPod), while the *brain* (registry, data-API, control-plane,
signer) stays on the VPS. This frees the VPS, gives agents real headroom, and is the same topology any
external contributor's CPU uses to join — the pod is just muscle you happen to own.

This is **already the intended architecture**: every worker initiates its connection *outbound* to the
brain, so it can live anywhere. Nothing in the brain needs to reach into the pod for normal operation.

---

## 1. Topology

```
            ┌──────────────────────── VPS (the brain — stays put) ───────────────────────┐
            │  registry / data-mesh   :18940   ← nodes announce + heartbeat here          │
            │  circuit-data-api       :18960   ← queries the registry on localhost         │
            │  agent control-plane    :18980   ← places agents, opens the session lease    │
            │  signer (CUSTODY/keys)  :18981   ← holds every agent wallet key              │
            └───────────▲───────────────────────────▲───────────────────────▲─────────────┘
                        │ announce/heartbeat (out)   │ poll for work (out)    │ sign trade (out)
                        │                            │                        │
            ┌───────────┴────────────────────────────┴────────────────────────┴───────────┐
            │                    CPU POD (the muscle — RunPod, 8 vCPU / 32 GB)              │
            │   6 × circuit-node-client  ──►  registryUrl = https://node.circuitllm.xyz     │
            │   1 × node-host            ──►  CONTROL_PLANE = https://cloud.circuitllm.xyz   │
            │        └─ spawns user agents ──► signer = https://signer.circuitllm.xyz       │
            └──────────────────────────────────────────────────────────────────────────────┘
```

The pod opens connections; the brain answers on the same connection. No inbound port is required on the
pod for the **node-host** path. (One nuance for the node-clients — see §8.)

---

## 2. What moves vs. what stays

| Component | Where | Why |
|---|---|---|
| circuit-node registry / data-mesh `:18940` | **VPS** | data-api queries it on localhost; it's the brain's directory of nodes |
| circuit-data-api `:18960` | **VPS** | x402 surface + revenue/payout hooks; queries the registry locally |
| agent control-plane `:18980` | **VPS** | placement authority + session lease (the fence) |
| signer `:18981` (keys) | **VPS** | custody root of trust — never on a worker box |
| **6 × circuit-node-client** | **POD** | mesh workers; announce **out** to the registry |
| **node-host + user agents** | **POD** | hosts agents; polls **out** to the control-plane |

---

## 3. The pod

- **Hardware:** plain x86-64 CPU, **no GPU**. 8 vCPU / 32 GB is a good size (capacity math in §6). Node ≥ 18.
- **Persistent volume (required).** RunPod pods are disposable; mount a network/persistent volume and keep
  on it: each node-client's `data/identity.json` (the ed25519 key whose pubkey **is** the nodeId — lose it
  and the node re-registers as a new address and drops out of the payout/trust map), each node's
  `config/client.json`, and the node-host data dir (`HOST_DATA_DIR`, agent state/logs).
- **Outbound internet** to the brain's public hostnames. No inbound ports needed for the node-host;
  node-clients may need one exposed port (§8).
- **Disk:** ~1–2 GB for the code installs (each repo ~150 MB incl. node_modules); agent data is a few MB
  each. 20 GB is plenty.

---

## 4. Expose the brain (the only VPS-side change)

Workers reach the brain by **public URL**, so three services must be reachable from the pod. Front each
with TLS (nginx/Caddy) — you already do this for `node.circuitllm.xyz`.

| Service | Suggested public host | Reached by | Auth on the wire |
|---|---|---|---|
| registry `:18940` | `node.circuitllm.xyz` *(already public)* | node-clients | node ed25519 signature (announce/ping) |
| control-plane `:18980` | `cloud.circuitllm.xyz` | node-host | `CIRCUIT_CLOUD_KEY` bearer |
| signer `:18981` | `signer.circuitllm.xyz` | agents (session token) | bearer (provision) + **session-token fence** (trade) |

### Securing the signer (it holds the keys — do this deliberately)

Even public, the signer is bounded: a trade needs a live **session token scoped to one agent + epoch**,
and the only verbs are `buy`/`sell` (no transfer/withdraw → no drain). The worst case from a leaked token
is one in-policy swap on one agent. Still, widen the surface carefully — pick one:

- **A. Private tunnel (recommended).** WireGuard between VPS and pod; the signer (and ideally the
  control-plane) listen only on the tunnel IP. The pod reaches them over the tunnel; nothing is exposed to
  the public internet. Strongest, and cheap to run.
- **B. Public + locked down.** TLS + the bearer key + a firewall allowlisting the pod's egress IP on
  `:18981`/`:18980`. Acceptable given the fence, but only if the pod has a stable IP.

Keep `CIRCUIT_SIGNER_MASTER_KEY` on the VPS only — it never goes to the pod. The pod only ever holds
rotating session tokens.

---

## 5. Config changes

### On the VPS (control-plane env)
```
CIRCUIT_SIGNER_URL=http://127.0.0.1:18981              # CP → signer, stays localhost
CIRCUIT_SIGNER_PUBLIC_URL=https://signer.circuitllm.xyz # handed to remote agents (THIS is the key line)
CIRCUIT_CLOUD_KEY=<bearer>                              # node-host must present the same
```
`CIRCUIT_SIGNER_PUBLIC_URL` is what the control-plane embeds in each agent's signer block — set it to the
pod-reachable URL or the tunnel IP. Leave the data-api pointed at `localhost:18940` (registry stays local).

### On the pod — node-clients (×6), `config/client.json`
```jsonc
"network": {
  "registryUrl":  "https://node.circuitllm.xyz",   // was http://localhost:18940
  "bootstrapUrl": "https://node.circuitllm.xyz"
},
"dataApiUrl": "https://api.circuitllm.xyz"          // was http://localhost:18960 (if used)
```
Copy each node's `data/identity.json` so it keeps its address. Everything else (region, ports) unchanged.

### On the pod — node-host (env, or `circuit agent host`)
```
CONTROL_PLANE=https://cloud.circuitllm.xyz
CIRCUIT_CLOUD_KEY=<same bearer as the CP>
NODE_ID=runpod-1
MAX_AGENTS=75            # capacity budget — see §6
MAX_MEMORY_MB=512        # per-agent ceiling (kills runaways)
MAX_CPU=8
HOST_DATA_DIR=/workspace/host         # on the persistent volume
CIRCUIT_AGENT_DIR=/workspace/circuit-agent   # the production workload, installed once
```
The signer URL is **not** set here — the control-plane hands it to each agent at placement.

---

## 6. How many agents fit on the pod

Measured footprints (real, from production): a trading agent (`circuit-agent/agent.js`) is **~140 MB RSS,
~1% of one core** (IO-bound — scans every few seconds, then sleeps). The 6 node-clients are ~95 MB each.

**On 8 vCPU / 32 GB, co-located with the 6 node-clients + node-host:**

```
container/OS base        ~0.8 GB
6 node-clients           ~0.6 GB
node-host                ~0.1 GB
─────────────────────────────────
fixed overhead           ~1.5 GB     →  ~30 GB free for agents
```

| Sizing basis | Math | Agents |
|---|---|---|
| Realistic (~140 MB/agent) | 30 GB ÷ 0.14 | **~200** |
| **Recommended target** | `MAX_AGENTS` | **~100** |
| Conservative start | — | **~75** |
| Worst case (every agent hits the 512 MB ceiling) | 30 GB ÷ 0.5 | **~60** |

**CPU is not the binding constraint** for these agents: 8 cores × 100% ÷ ~1% each ≈ hundreds. Memory is.
But tick *bursts* (many agents scanning at once) argue for headroom — anchor on **~100**, start at 75,
raise `MAX_AGENTS` while watching RAM + load.

**Scale-to-any-pod rule of thumb:**
```
agents ≈ (RAM_GB − 1.5) / 0.15        # memory-bound, ~150 MB/agent with slack
         capped by MAX_MEMORY_MB (512 MB worst case) and a CPU-burst margin
```
So a 16 GB pod ≈ ~90 comfortable; 64 GB ≈ ~400 by memory (CPU/cores become the real ceiling there).
Heavier agents (real local compute, not just IO) shift toward the worst-case column — plan ~50/32 GB then.

---

## 7. Migration runbook

Do it incrementally — one node first, verify, then the rest. Nothing here moves funds.

1. **Provision the pod** + persistent volume. Install Node ≥ 18, clone `circuit-node-client` and
   `circuit-agent-cloud` (+ the production `circuit-agent` workload). `npm ci` in each.
2. **Expose the brain** (§4): bring up `cloud.` + `signer.` hosts (or the WireGuard tunnel); set
   `CIRCUIT_SIGNER_PUBLIC_URL` + `CIRCUIT_CLOUD_KEY` on the VPS control-plane and restart it.
3. **Move node #1:** copy `node1/config/client.json` + `node1/data/identity.json` to the pod, edit
   `registryUrl` → public, start it. Confirm on the VPS it appears in the registry
   (`curl localhost:18940/api/network/nodes` shows node1 with the *same* address) and heartbeats.
   **Then stop node1 on the VPS.**
4. **Verify the data path still works** (§8): hit a data-api endpoint that depends on circuit-node scoring
   (e.g. `/api/token-info?mint=…`) and confirm it still returns. If it fails, you're in the inbound-routing
   case — see §8 before moving the rest.
5. **Move nodes 2–6** the same way, one at a time, verifying the registry count each step.
6. **Stand up the node-host on the pod** (§5 env), `circuit agent host --max-agents 75`. Confirm it
   registers with the control-plane (`curl cloud.circuitllm.xyz/v1/nodes`).
7. **Deploy a paper test agent** to the pod, confirm it runs, heartbeats, and **signs a paper trade
   through the remote signer** (the round-trip that proves the whole topology). Then enable live agents.
8. **Decommission** the node-host that was running idle on the VPS.

**Rollback (any step):** point that worker's `registryUrl` / `CONTROL_PLANE` back at `localhost`, restart
it on the VPS, stop the pod copy. Because identities travel with the node, flipping back is lossless.

---

## 8. The one thing to verify: how scoring work reaches a node

Two ways work reaches a worker:

- **Pull / outbound (the common, NAT-friendly path).** The worker dials out and pulls/streams work — e.g.
  each node's LLM worker already connects out to `coordinatorUrl` (a remote runpod today). Works through
  any NAT, zero inbound config. The node-host is purely this model.
- **Push / inbound.** If the registry at `:18940` **routes** a scoring request *into* a node (data-api →
  registry → node), that node must be reachable. A RunPod pod can expose a TCP port, so this is solvable,
  but it's the case to check.

**Action (step 4 above):** after moving the first node, test a circuit-node-scored data-api endpoint.
- If scoring still works → `:18940` computes/holds it centrally and the node-clients are liveness/mesh
  participants (announce + heartbeat only). Moving them is purely outbound — done.
- If scoring breaks → it's routed to nodes. Either expose the node's port on the pod and register that
  public address, or front it with the NAT relay. Resolve this before moving all six.

This is the only open question in the migration; everything else is outbound and clean.

---

## 9. Operations

- **Pod restart:** with identities + `HOST_DATA_DIR` on the persistent volume, nodes keep their addresses
  and agents reschedule cleanly (the control-plane re-opens sessions; the epoch fence supersedes orphans).
- **Monitoring:** watch pod RAM (the binding resource), 1-min load vs. cores, and the control-plane's
  view of the node-host (`available` budget). Raise `MAX_AGENTS` only while RAM has slack.
- **Scaling out:** more capacity = another pod running another node-host with its own `NODE_ID`, pointed
  at the same control-plane. The scheduler bin-packs across them by agent count automatically — which is
  exactly how third-party contributor CPUs will join later.
```
