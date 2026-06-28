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

## Controlled egress — BUILT (sidecar) + VERIFIED

Untrusted agents that need to reach *allowed* Circuit hosts (data-api, inference, signer) go through an
egress proxy + `lib/netguard.js` allowlist. The original design ran the proxy as a **host process bound
to the bridge gateway**, which a container on an `--internal` net could never reach (and the config even
pointed `HTTPS_PROXY` at the wrong bridge). **Fixed** — the proxy now runs as a **sidecar container** on
two networks (`node-host/host.js startEgressSidecar` + `node-host/egress-proxy-main.js`):
- the agent attaches ONLY to the `--internal` egress network (`CIRCUIT_EGRESS_NETWORK`) — no route out;
- the proxy container attaches to that internal net AND an external bridge (`CIRCUIT_PROXY_EXTERNAL_NETWORK`,
  default `bridge`), so it — and only it — can reach the allowlisted hosts;
- the agent's `HTTPS_PROXY` resolves the proxy by container name over docker DNS.

No fragile `DOCKER-USER` rules, no host-process reachability assumptions. The proxy is itself hardened
(read-only, cap-drop ALL, no-new-privileges). The same `egress-proxy.js` allowlist + anti-DNS-rebind
logic; only its placement changed.

**Verified live (`test/egress-sidecar.test.mjs`, docker-gated):**
- agent → allowlisted host via proxy → **200** ✓
- agent → non-allowlisted host via proxy → **denied** (`deny … not-allowlisted`) ✓
- agent → direct internet (bypassing proxy) → **no route** ✓

### One follow-on for Node agents
The proxy is enforced at the network layer (the agent's *only* route is the proxy), but a Node workload
must actually *use* `HTTPS_PROXY` — global `fetch`/undici needs a `ProxyAgent` (or Node's env-proxy
support), unlike `curl`. A first-party agent image can wire undici's `EnvHttpProxyAgent` as the default
dispatcher so agent code "just works" through the allowlist.

## To make a node actually host untrusted agents
1. operator in the `docker` group (so `detectOciRuntime()`'s `docker info` passes) — done on this box
2. `CIRCUIT_EGRESS_NETWORK=circuit-egress` (the `--internal` net created here)
3. for controlled egress: the sidecar-proxy fix above (until then, untrusted = fully isolated)
4. trusted first-party / paper agents keep using the `node` runtime (no container needed)
