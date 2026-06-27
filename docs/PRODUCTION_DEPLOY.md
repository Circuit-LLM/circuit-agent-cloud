# Production Deployment — Agent Cloud Control Plane

Security-first standup of the agent-cloud control plane for a **multi-tenant production model
where outside machines join**. This is the live runbook for the bootstrap deployment on the
Watchtower VPS (`76.13.107.150`).

## Topology

```
                        outside node-hosts (untrusted operators)
                                     │  TLS (node-auth ed25519)
                                     ▼
  nginx  agents.circuitllm.xyz:443  ──►  control-plane  127.0.0.1:18980   (registry / scheduler / placement)
                                                  │  CIRCUIT_SIGNER_KEY bearer, localhost only
                                                  ▼
                                          signer  127.0.0.1:18981          (custody — NEVER exposed)
                                                  ▲
                                          node-host (this box)  ──► agentd / circuit-agent workloads
```

Two processes are **localhost-bound and never leave the box**: the control plane (fronted by
nginx for TLS) and the **signer** (custody — no public route at all, by design).

## Services (systemd --user)

| unit | bind | role |
|------|------|------|
| `circuit-signer.service`        | `127.0.0.1:18981` | custody. AES-256-GCM-sealed seeds + master key. buy/sell-only. at-most-one fence (monotonic epoch). |
| `circuit-control-plane.service` | `127.0.0.1:18980` | registry / scheduler / placement. Strict multi-tenant auth. |
| `circuit-node-host.service`     | (egress only)     | first-party bootstrap CPU. Registers signed (node-auth). `SANDBOX=node`. |

Launchers `run-{signer,control-plane,node-host}.sh` pull every secret from Infisical **at start**,
so secrets live in the process env — never on disk, never in the unit files. They are
operator/host-specific (they reference the local Infisical helper) and are intentionally **not
committed**.

```bash
systemctl --user status circuit-signer circuit-control-plane circuit-node-host
journalctl --user -u circuit-control-plane -f
```

## Security posture (enforced, verified live)

- **Bind safety** — signer + control-plane both `127.0.0.1` only (`ss -tlnp | grep 1898`).
- `CIRCUIT_REQUIRE_NODE_AUTH=1` — joining nodes must prove a node identity (ed25519-signed headers).
- `CIRCUIT_REQUIRE_OWNER_AUTH=1` — owner routes (create / withdraw / export / …) need a wallet signature.
- `CIRCUIT_OWNER_RATE_PER_MIN=60` — per-owner rate limit.
- `CIRCUIT_CLOUD_KEY` — admin bearer; also required to **promote a node to trusted**. A node that
  self-reports caps is NOT trusted until an operator promotes it (`PUT /v1/nodes/:id/trust`).
- `CIRCUIT_SIGNER_KEY` — control-plane ↔ signer bearer.
- `CIRCUIT_SIGNER_MASTER_KEY` — 32 bytes, unlocks all custodied wallets. Sealed `0600` on disk +
  backed up to Infisical (base64). Losing it loses every custodied wallet.
- Verified: anon `GET /v1/nodes` → 401; unauthenticated `PUT …/trust` → 401.

## Exposing the control plane for outside machines (nginx + TLS)

The signer stays localhost-only. Only the **control plane** is exposed, at `agents.circuitllm.xyz`.
Template lives at `/etc/nginx/sites-available/agents.circuitllm.xyz` (proxies → `127.0.0.1:18980`,
adds the `circuit_cloud` rate-limit zone, and blocks `…/trust` from the public edge as
defense-in-depth). **Blocked on a DNS A record** — until that resolves, no cert can issue.

```bash
# 1. DNS: A  agents.circuitllm.xyz  ->  76.13.107.150     (operator action — at the registrar)
# 2. Enable + issue TLS:
sudo ln -s /etc/nginx/sites-available/agents.circuitllm.xyz /etc/nginx/sites-enabled/
sudo certbot --nginx -d agents.circuitllm.xyz
sudo nginx -t && sudo systemctl reload nginx
```

Outside operators then join with `CONTROL_PLANE=https://agents.circuitllm.xyz` (see
`docs/REMOTE_WORKER_POD.md`).

## ⚠️ Custody caveat — before holding real outside funds

The v1 **signer is custodial**: Circuit holds the sealed seeds. That is acceptable for first-party
/ paper / bootstrap workloads, but **NOT** for holding outside operators' real funds at scale. The
secure upgrade path is the **non-custodial vault** (`circuit-agent-vault` Anchor program — agent on
untrusted CPU trades any token but can never withdraw; owner is sole withdraw authority; Circuit
holds no keys). Phase 5 (off-chain: agent/CLI drive the vault + retire the signer) is the gate
before a public custody launch. See `docs/AGENT_VAULT.md` and `SECURITY.md`.
