# Security Review — Circuit SDK + Agent-Cloud Container System (2026-06-27)

Five independent adversarial reviewers + author verification.

## Remediation status (implemented 2026-06-27)

**FIXED + tested:**
- **A1** oci spec requires an isolated `--network`; node fails closed (refuses oci) unless
  `CIRCUIT_EGRESS_NETWORK` is set — HTTPS_PROXY alone is no longer trusted as containment.
- **A2/A3** egress proxy + `pullBytes` resolve once and connect to the **validated IP** (custom
  lookup / `net.connect(ip)`) — DNS-rebinding TOCTOU closed. **A4** port pinned to 443. **A5** netguard
  rewritten (IPv6 v4-mapped/compat + multicast/reserved/broadcast/benchmarking ranges). **A6** proxy
  binds `CFG.proxyBind`. **A7** robust CONNECT parsing + host normalization.
- **B1** `entry` validated as a safe in-bundle filename (publish + verify). **B2** `egress` + `resources`
  are now **signed**. **B3** `resources.maxMemoryMb` capped to the operator budget. **B5** pull size cap.
- **C1** `manifest.agentId` bound to the agent (CP adopts it as the id; node verifies). **C3** owner
  change re-validates the binding.
- **D1** keyed `CIRCUIT_RPC_URL` withheld from untrusted bundles (keyless substitute or absent).
  **D2** `spec.env` can't set `NODE_OPTIONS`/`LD_*`/etc.
- **E1** x402 recipient-pin + cumulative budget. **E3** null-blockTime no longer auto-fresh. **E4**
  inference receipt binds only the reserved `aiVerdict` input.

**Documented / by-design / deployment:**
- **E2** `MemoryReplayStore` flagged dev-only (prod needs a shared store). **E5** whole-token CIRC
  rounding matches the server byte-for-byte — intentional pricing granularity, not a desync.
- **Image pin** (`node:20-bookworm-slim@sha256:PIN_ME`) + a **tight seccomp profile** are slots wired in
  `oci.js`/`CFG.seccompProfile` — fill them at deploy.

**Multi-tenant hardening — IMPLEMENTED 2026-06-27 (strict-mode, off by default for own-fleet):**
- **C2 (per-owner auth + authz):** every mutating request is wallet-signed (`lib/owner-auth.js`); the CP
  verifies + authorizes per-agent — a caller can only act on agents they own (`CIRCUIT_REQUIRE_OWNER_AUTH=1`).
  Closes the shared-bearer IDOR. CLI signs automatically.
- **C4 (node-identity):** nodes sign register/heartbeat/report (`lib/node-auth.js`); nodeId is TOFU-bound
  to its key, and only the node running an agent may report it (`CIRCUIT_REQUIRE_NODE_AUTH=1`).
- **C5 (attested placement):** an `oci` (untrusted) bundle is placed only on a `node.trusted` node, set
  via admin `PUT /v1/nodes/:id/trust` — never the node's self-reported caps.
- **B6/B7 (node-runtime gate):** the host refuses an unsandboxed `node`-runtime bundle from a non-first-
  party publisher when `CIRCUIT_FIRST_PARTY_KEYS` is set (untrusted ⇒ oci).
- **E2 (durable replay):** `FileReplayStore` (cross-process) for the x402 verifier; per-owner create
  rate limit (`CIRCUIT_OWNER_RATE_PER_MIN`).

**Still operational (deployment, not code):** **TLS** on the CP↔node channel (assignment *integrity* is
already covered by the agentId binding + signed manifest + node re-verification; TLS is the confidentiality
layer); a **Redis-backed** replay store for multi-HOST; the attestation/probation system that *feeds*
`node.trusted`; and pinning the base-image digest + a tight seccomp profile.

---
 Scope: `circuit-sdk` (x402, attest,
agent/custody, data, wallet, core) and `circuit-agent-cloud` bundle/container hosting (B0/B1/B2:
`lib/bundle*.js`, `lib/netguard.js`, `node-host/{env,egress-proxy,oci,host}.js`, `control-plane`,
`lib/proto.js`). "✓verified" = re-read against source by the author.

## Threat-model context (read first)

The current deployment is **own-fleet / single-tenant B1**: Circuit runs its own agents on its own
nodes, and the agent points at Circuit's own data-api. **B2 (untrusted bundles from strangers) is not
live and cannot even run here** (no usable container runtime → `detectOciRuntime()` = null, fails safe).
So **none of these are "the running system is compromised."** They sort into:

- **(A) Network isolation broken** — defeats the *B2* untrusted-egress guarantee. Must-fix before B2 ships.
- **(B) Bundle-verification gaps** — weaken the "only verified bytes run" invariant *regardless of tenancy*.
- **(C) Multi-tenant trust gaps** — must-fix before untrusted *publishers/operators*; partly known/documented.
- **(D) Secret hygiene** — a hosted bundle gets more than it should.
- **(E) SDK x402/attest** — matter whenever an agent talks to a non-trusted endpoint.
- **(F) Defense-in-depth / DoS / hardening.**

---

## A. Network isolation (the B2 headline — two independent breaks)

### A1 — CRITICAL ✓ Container has no `--network`; the egress proxy is advisory only
`node-host/oci.js:36-55`. The spec sets `HTTPS_PROXY`/`https_proxy` but never `--network`, so the
container joins Docker's default bridge with a full default route. `HTTPS_PROXY` is a *client convention*;
a hostile agent ignores it and does `net.connect(443,'169.254.169.254')` or hits the LAN/any host
directly. The entire `egress-proxy.js`/`netguard.js` defense is bypassed for OCI bundles.
**Fix:** put the container on an `--internal` network (or `--network none` + a single veth to the proxy)
and drop all egress except to the proxy via host `DOCKER-USER` iptables. `HTTPS_PROXY` is not containment.

### A2 — CRITICAL ✓ DNS-rebinding TOCTOU: proxy connects to the hostname, not the validated IP
`node-host/egress-proxy.js:50,57`. `egressDecision`→`assertPublicHost(host)` does DNS lookup #1 to
validate; then `net.connect(port, host)` does its OWN lookup #2. An attacker controlling DNS for an
allowlisted host returns a public IP to #1 and `169.254.169.254`/LAN/loopback to #2. (Empirically
confirmed by the reviewer with a flip-lookup harness.)
**Fix:** resolve once, validate every returned address, and connect to the validated **IP literal**, not
the hostname. Have `assertPublicHost` return the vetted address; `net.connect({host: ip, port})`.

### A3 — HIGH ✓ Same TOCTOU in `pullBytes`
`lib/bundle-store.js:45-46`. `assertPublicHost(u.hostname)` then `fetch(url)` re-resolves. Lower live
risk (the node derives the URL from its *own* trusted store base, not publisher input) but the function
defends in depth precisely for the untrusted case. **Fix:** pin to the validated IP (custom `lookup`/agent).

### A4 — HIGH No destination-port restriction
`egress-proxy.js:48-49,57`. `port = parseInt(portStr || '443')` — any port is honored. A bundle can
`CONNECT allowed-host:22` / `:5432` / `:6379` if an allowlisted upstream co-hosts SSH/DB/admin.
**Fix:** pin to 443 (or the explicit port of the resolved allowlist URL).

### A5 — HIGH netguard IP-range gaps
`lib/netguard.js`. `isPrivateV6` misses fully-expanded IPv4-mapped (`0:0:0:0:0:ffff:a9fe:a9fe`) and
IPv4-compatible (`::a9fe:a9fe`) forms → pass as literals. `isPrivateV4` misses `255.255.255.255`,
multicast `224.0.0.0/4`, reserved `240.0.0.0/4`, `192.0.0.0/24`, benchmarking `198.18.0.0/15`. Only bites
with A2-style rebind or an IP on the allowlist, so defense-in-depth — but fix alongside A2/A4.
**Fix:** parse with `net.isIP()` to bytes (don't string-match v6); extract embedded v4 from any
v4-mapped/compat form; add the missing CIDRs.

### A6 — MEDIUM Proxy binds `0.0.0.0` (contradicts its own comment), reachable by every container
`host.js:117` `proxy.listen(0,'0.0.0.0')` while egress-proxy.js:36 says "bound to loopback." Each
per-agent proxy carries a *different* allowlist; any container can scan `172.17.0.1:*` and route through
another agent's proxy. (Moot while A1 holds — the agent doesn't need the proxy — but becomes the bypass
once A1 is fixed.) **Fix:** bind to the per-agent network's gateway only, or one netns-isolated proxy/agent.

### A7 — MEDIUM IPv6 CONNECT target mis-parsed; A8 allowlist not normalized
`egress-proxy.js:48` `split(':')` breaks on `[::1]:443` (fails closed today). Allowlist match is
exact-string (case/trailing-dot/punycode not normalized; fails closed). **Fix:** parse with
`new URL('https://'+req.url)`; lowercase + strip trailing dot + punycode before compare.

---

## B. Bundle verification (weaken "only verified bytes run", any tenancy)

### B1 — HIGH ✓ `entry` accepts `..` → execution escapes the verified tree
`lib/bundle.js:92` `/^[\w.-]+$/` matches `..`. `entry:'..'` (signed) → node runs `path.join(cacheDir,'..')`
= the parent cache dir; oci runs `node /app/..` = `/`. A "valid" manifest steers execution outside the
content-verified subtree. **Fix:** reject `.`/`..`/separators and assert
`path.resolve(cacheDir,entry).startsWith(path.resolve(cacheDir)+sep)`.

### B2 — HIGH ✓ Manifest signature omits `egress` and `resources`
`lib/bundle.js:25-35` signs `{agentId,entry,runtime,schema,sdk,sha256}` only — but the node feeds
`manifest.egress` into the egress allowlist (`host.js` oci branch) and `resources` into the memory cap.
The spec says these are signed; they aren't. Anyone who can mutate the in-flight manifest widens the
egress allowlist (reach signer/data/rpc) or the resource cap on a still-valid signature.
**Fix:** include `egress` (sorted) + `resources` (fixed key order) in `manifestSigningBytes`.

### B3 — MEDIUM ✓ `resources.maxMemoryMb` not capped to the operator budget
`host.js` oci branch + `applyCgroup`: `a.spec?.resources?.maxMemoryMb || CFG.maxMemoryMb` (no `Math.min`).
A request with `maxMemoryMb: 999999` is honored verbatim → memory starvation. **Fix:**
`Math.min(Number(spec.maxMemoryMb)||CFG.maxMemoryMb, CFG.maxMemoryMb)`; mirror pids/cpu.

### B4 — MEDIUM Node trusts the *assignment* manifest, never the store's sha-bound copy
`host.js:99-115`. The store keeps `<sha>.manifest.json` (bound to the bytes at put time) but the node
uses `a.bundle.manifest` from the assignment. Combined with B2, unsigned fields ride entirely on
transport trust. **Fix:** verify the store's stored manifest, or reconcile assignment==stored.

### B5 — MEDIUM No size cap on pull/extract → gzip-bomb / disk-fill DoS of the node-host
`bundle-store.js:49,57` buffer the whole response; `bundle.js` `tar -xzf` has no size/member guard, and
the node-host runs *outside* any cgroup. A valid-sha multi-GB/zip-bomb tarball OOMs the host or fills the
cache. **Fix:** cap `Content-Length`/stream with a byte limit; bound extraction (size/member count).

### B6 — LOW Reversible `chmod a-w` + `.ok` marker → same-uid cache poisoning (B1 node runtime)
`host.js:93-107`. The node-runtime bundle runs as the operator uid and can `chmod u+w` and rewrite the
cached tree; a later same-sha run skips re-verify (`.circuit-ok`). Bounded because node-runtime is
trusted-only. **Fix:** re-hash on cache hit, or own the cache by a separate uid / RO bind-mount.

### B7 — LOW Symlink members extracted (GNU tar blocks the dangerous ones; don't rely on it)
`bundle.js:70`. GNU tar 1.35 blocks `../` and symlink-write-through, but an absolute symlink member lands
in the tree. **Fix:** reject non-regular members explicitly (don't depend on the host tar).

---

## C. Multi-tenant trust (must-fix before untrusted publishers/operators)

### C1 — HIGH ✓ Manifest `agentId` is signed but never bound to the agent
`control-plane/server.js` `assertBundleOwnerBinding` + `lib/bundle.js verifyBundle`. Nothing checks
`manifest.agentId === agent.id`. A publisher can attach one signed manifest to *any* agent they own
(fresh CP-generated id + wallet). Defeats the documented per-agent binding. **Fix:** require
`manifest.agentId === agent.id` in both the CP binding (thread the new id in — it's currently computed
*after* the check) and `verifyBundle`.

### C2 — HIGH Custody routes open when `CIRCUIT_CLOUD_KEY` unset; no per-owner authz (IDOR)
`control-plane/server.js auth()`, `signer/server.js`. One global optional bearer; unset = fully open
(`/export` returns a wallet key, `/withdraw`, `/owner`, `/delete`). Even when set, any bearer holder can
act on any agent by id — `PUT /owner`→attacker then `withdraw` = theft for *any* agent. The signer code
itself concedes "a multi-tenant deployment must add per-owner auth." **Fix:** fail closed on mutating
routes when KEY unset (only `/health` open) or bind loopback-only; add per-owner authorization on `:id`.

### C3 — MEDIUM ✓ `PUT /owner` doesn't re-validate the bundle binding
`control-plane/server.js` owner route. `assertBundleOwnerBinding` runs only at create; changing `owner`
leaves a stored bundle whose publisher no longer matches (breaks the agent at the node, and silently
falsifies the CP's "publisher==owner" invariant). **Fix:** re-run the binding on owner change / any spec
mutation; reject if a bound bundle would no longer verify.

### C4 — MEDIUM Report/heartbeat node-ownership IDOR
`control-plane/server.js` `/report` + heartbeat. Any bearer holder can POST health/logs for any agent id
(no `a.nodeId === caller` check) and heartbeat as another `nodeId`. Poisons dashboards / masks failover.
**Fix:** authenticate node identity (ed25519 node keys already exist) and require `a.nodeId === caller`.

### C5 — MEDIUM Self-reported `caps.sandbox` is not a security boundary
`lib/proto.js nodeSatisfies` + register. A malicious operator registers `caps.sandbox:'oci'` to attract
untrusted bundles, then runs them with no container (de-sandbox → read/run the bytes). Custody already
protects *funds* (off-box, buy/sell-only, fenced); the residual is bundle-code/secret confidentiality —
and untrusted bundles get no secrets, only endpoint URLs. **Fix:** gate `oci` placement on
attested/probation-passed nodes; document that bundle bytes are not confidential and operators are trusted
to honor advertised sandbox. (Inherent to untrusted CPUs — needs the existing trustless-verification system.)

---

## D. Secret hygiene

### D1 — HIGH ✓ `CIRCUIT_RPC_URL` (often a keyed Helius URL) forwarded to untrusted bundles
`node-host/env.js:16` (in `ENDPOINT_ENV`, forwarded at every trust level) + `host.js:165`. The comment
claims B2 repoints it at the proxy "rather than the operator's keyed upstream" — **that rewrite does not
exist**. An untrusted bundle reads `process.env.CIRCUIT_RPC_URL` and exfiltrates the operator's paid RPC
key. (oci.js does NOT drop it either.) **Fix:** for untrusted bundles, substitute proxy/proxied endpoints
for credential-bearing URLs, or strip the key. "URLs only, never secrets" is violated when the URL *is*
the secret.

### D2 — LOW `spec.env` passes process-influencing vars
`env.js:69-73` blocks `CIRCUIT_AGENT_*`/`CIRCUIT_SIGNER_*` and exact secret names but allows
`NODE_OPTIONS`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`, `npm_config_*`. For the same-uid B1 path,
`NODE_OPTIONS=--require /data/evil.js` is code-load control. **Fix:** denylist process-influencing vars
(or strict additive allowlist for `spec.env`).

---

## E. SDK — x402 / attest

### E1 — HIGH ✓ x402 spend cap is per-call only; recipient+amount attacker-controlled → wallet drain
`packages/x402/src/client.ts:101-106`. Only `quote.amountRaw > maxSpendRaw` is checked; `recipient` +
`amountRaw` come straight from the 402 body (`parse402`) and are never validated against the Circuit
treasury or a cumulative budget. A malicious/compromised/MITM'd endpoint answers every request with
`recipient=attacker, amountRaw=maxSpend` → `N × maxSpend` drained over a tight agent loop. (Not live
against Circuit's own data-api, but the SDK is meant to point anywhere.) **Fix:** pin `recipient` to the
configured treasury; add a cumulative session budget; optionally cross-check amount vs the price oracle.

### E2 — MEDIUM Replay store is in-memory per-process (multi-worker)
`packages/x402/src/verify.ts`. The default `MemoryReplayStore` is per-process; behind multiple workers a
valid payment is consumed by A and rejected by B on the client's free retry (paid-but-denied), and an old
payment can replay across workers. **Fix:** require a shared (Redis/disk) ReplayStore for prod; flag the
in-memory default dev-only.

### E3 — MEDIUM `blockTime: null` bypasses the freshness window
`packages/x402/src/verify.ts:122-125`. `(tx.blockTime ?? now())` makes a null-blockTime tx "fresh," so
the 5-min replay-expiry is a no-op for such txs (only the per-process store then guards). **Fix:** require
a confirmed `blockTime` for payments, or don't treat null as fresh.

### E4 — MEDIUM `inference-receipt` evidence ignores the input name
`packages/attest/src/evidence.ts:164`. Unlike signed-quotes/zktls (which bind `ev.data[input]===value`),
receipts only check `verdict===value` — so a single receipt "backs" *any* required input whose value
equals the verdict string. **Fix:** bind receipts to a specific input name (e.g. `aiVerdict`).

### E5 — MEDIUM/LOW `circRawFromUsd` rounds up to a whole CIRC token before scaling
`packages/x402/src/quote.ts:13-17` `BigInt(Math.ceil(circAmount) * 10**6)` → `usd=0.0001,rate=1` charges
1.000000 CIRC not 0.000100 (10,000×). Security-relevant only as a price-sanity bound (E1); otherwise an
overcharge/correctness bug — verify it matches the server's `x402.js`. **Fix:** ceil in raw units:
`BigInt(Math.ceil((usd/rate)*10**6))`.

### E6 — LOW `acceptedKeys` defaults to `{}` (off-chain gate becomes advisory); E7 `stableStringify`
doesn't reject non-finite numbers (cross-impl byte-identity risk — add golden vectors Py↔JS); E8
`Wallet.swap` signs Jupiter's returned tx without inspecting instructions (defense-in-depth: validate the
tx only touches the user's accounts before signing).

---

## What's SOLID (don't regress)

- **B0 env curation** — never inherits `process.env` wholesale; untrusted bundles get no `SECRET_ENV`;
  `spec.env` can't shadow identity vars or smuggle exact secret names; off-box session token, never the key.
- **SSRF on the bundle pull root cause is closed** — node derives the URL from its own trusted store base
  + `^[0-9a-f]{64}$` sha, never publisher `b.url`; https-only; redirects refused; local backend realpath-
  confined to the store root. (The residual is the DNS-rebind TOCTOU A3, not URL substitution.)
- **Hash-before-unpack ordering** — `verifyBundle` checks sha→sig→owner before any unpack/run.
- **`publisherPubkey` excluded from signed bytes** → swapping the key invalidates the sig; owner-binding
  ties it down. No substitution on *signed* fields.
- **Data-client path injection — NOT vulnerable**: every interpolated `mint`/`poolAccount` uses
  `encodeURIComponent`; queries via `URLSearchParams`.
- **attest `verifyEvidence` key-binding correct** (checks `acceptedKeys[ev.key]` role *before* verifying;
  kind→role prevents data-key signing inference; ed25519-only, no algo confusion; signed payload excludes
  key+sig). **decisionGate** re-runs the rule + binds inputs + `sameIntent` — forged token/size/price rejected.
- **Custody**: signing key off-box; `Intent` has no transfer/withdraw kind; session epoch+token fence;
  withdraw destination = committed owner only; no key in logs/errors; `0600` identity file.
- **OCI flags that ARE present are correct** (`--read-only`, `--cap-drop ALL`, `no-new-privileges`,
  non-root, `--pids-limit`, `--memory`==`--memory-swap`, RO bundle mount, tmpfs noexec) and **no docker
  socket mounted**. **Honest sandbox auto-detect** (`oci` only if a runtime works → fails safe).
- **Proxy fails closed** (deny-by-default allowlist, plain-HTTP forward disabled). **`a.id` is
  server-generated** (no path/arg injection via the documented API). **Body size limit + strict JSON.**
- Decimal/hex/octal IPv4 short forms are NOT a bypass (fall to the DNS path, which normalizes + blocks).

---

## Deduped severity tally

| | Network (A) | Bundle (B) | Multi-tenant (C) | Secrets (D) | SDK (E) |
|---|---|---|---|---|---|
| CRITICAL | A1, A2 | — | — | — | — |
| HIGH | A3, A4, A5 | B1, B2 | C1, C2 | D1 | E1 |
| MEDIUM | A6, A7 | B3, B4, B5 | C3, C4, C5 | — | E2, E3, E4 |
| LOW | — | B6, B7 | — | D2 | E5, E6, E7, E8 |

**Recommended fix order** (cheap + high-impact first):
1. **A1 `--network` internal + A2/A3 connect-to-validated-IP + A4 port-pin** — restores the B2 egress guarantee.
2. **B1 `entry` validation + B2 sign egress/resources + B3 cap resources** — closes the verification escapes.
3. **D1 RPC-URL handling for untrusted bundles** — stop leaking the keyed RPC URL.
4. **E1 pin x402 recipient + cumulative budget** — stop attacker-controlled drain.
5. **C1 bind `manifest.agentId` + C3 re-validate on owner change** — bundle-binding integrity.
6. **C2 fail-closed/loopback auth + C4 node-ownership + C5 attested caps** — before any untrusted operator.
7. A5/A6/A7 netguard+proxy hardening, B4/B5 manifest-from-store + size cap, E2-E5, D2, B6/B7 — defense-in-depth.
</content>
