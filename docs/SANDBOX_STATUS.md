# Untrusted-Agent Sandboxing — Operational Status

Deep-dive + operationalization of the B2 sandbox (running an UNTRUSTED bundle from another publisher on
an operator's machine). Verified live on the VPS (docker 29.1.3).

## How an agent moves machine-to-machine (this part is built + tested)

An agent is a **content-addressed, signed bundle**, not a long-lived container that migrates:
1. A publisher packs their agent dir → a tarball; `lib/bundle.js` content-addresses it (sha256) and the
   owner Ed25519-signs a manifest (entry, runtime, egress, resources, agentId, publisherPubkey).
2. The control plane schedules the agent (with the bundle block) to a node.
3. The node-host `resolveBundle()` **pulls by content hash from its OWN trusted store** (never the
   publisher's URL → SSRF-safe), **verifies** sha256 + signature + owner/agentId binding, unpacks to a
   read-only tree, and runs it.
4. On reschedule/failover the *new* node repeats pull→verify→run. So "moving machines" = the same signed
   bytes re-materialised + re-verified on each host. No unverified byte ever executes.

Covered by `test/{bundle,bundle-binding,ssrf}.test.mjs` (all green).

## Isolation core — BUILT + now PROVEN (verified live)

`node-host/oci.js buildContainerSpec` runs the verified tree in a hardened container. Verified on the VPS:

| property | flag | live result |
|---|---|---|
| no internet | isolated `--internal` net | `fetch(1.1.1.1)` → **ENETUNREACH** ✓ |
| read-only rootfs | `--read-only` | write to `/etc` → **EROFS** ✓ |
| non-root | `--user 65534:65534` | uid == 65534 (nobody) ✓ |
| no caps / no priv-esc | `--cap-drop ALL` + `no-new-privileges` | ✓ |
| only `/data` writable | RO bundle mount + tmpfs `/tmp` | no stray writable mounts ✓ |
| pinned rootfs | digest, not tag | **fixed** — was `sha256:PIN_ME`, now a real digest |

Plus: pids/memory caps, content-addressed RO bundle mount. **A fully-isolated (`--internal`) untrusted
agent cannot reach the internet, the host, or escape the container.**

## The gap — controlled egress (FOUND, not yet fixed)

Untrusted agents that need to reach *allowed* Circuit hosts (data-api, inference, signer) go through a
per-agent egress proxy + `lib/netguard.js` allowlist. **This path was never functional:**
- the proxy runs as a **host process bound to the bridge gateway**, but a container on an `--internal`
  net can't reach the gateway at all, and on a normal bridge the container-→-host-gateway path didn't
  connect either;
- the config defaults point the container's `HTTPS_PROXY` at the **wrong bridge** (`172.17.0.1`, the
  default docker bridge, not the egress net's gateway).

So today untrusted agents can only run **fully network-isolated**. Controlled egress needs a redesign.

### Recommended fix (no host iptables)
Run the egress proxy as a **sidecar container on two networks**:
- `circuit-egress-internal` (`--internal`): the agent attaches ONLY here.
- the proxy container attaches to BOTH that internal net AND a normal bridge.
- agent → proxy (container-to-container over the internal net) → internet (proxy's external interface).

The agent has no path out except through the proxy container; no fragile `DOCKER-USER` rules, no
host-process reachability assumptions. `egress-proxy.js` logic (allowlist + netguard) stays; only its
*placement* changes (host process → sidecar container).

## To make a node actually host untrusted agents
1. operator in the `docker` group (so `detectOciRuntime()`'s `docker info` passes) — done on this box
2. `CIRCUIT_EGRESS_NETWORK=circuit-egress` (the `--internal` net created here)
3. for controlled egress: the sidecar-proxy fix above (until then, untrusted = fully isolated)
4. trusted first-party / paper agents keep using the `node` runtime (no container needed)
