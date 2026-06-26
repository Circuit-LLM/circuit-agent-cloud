# Agent Vault — non-custodial on-chain custody (devnet build spec)

**Status:** SPEC / pre-build. Target: a working, fully-tested **devnet** deployment. Mainnet is a later
flip gated on an audit.

**One line:** an on-chain Solana program that lets an agent on an untrusted CPU **trade any token but
never withdraw**, while the user keeps sole withdrawal authority and Circuit holds no keys at all. It
replaces — and deletes — the custodial off-box signer.

---

## 1. What we're solving (holistically)

Circuit runs autonomous trading agents on a mesh of **untrusted contributor CPUs**. Three forces are in
permanent tension, and every prior design could satisfy only two:

1. **Non-custodial** — Circuit must hold no keys; the user alone controls their funds.
2. **Autonomous on untrusted hardware** — the agent trades by itself, on a stranger's CPU, with no human.
3. **Trade anything** — arbitrary SPL / Token-2022 tokens via Jupiter, not a fixed venue's market list.

Today's **off-box signer** gives up #1: one server holds every agent's private key (sealed at rest, but
the master key sits beside it). It protects users from the *host* but not from *Circuit* — a server breach
or rogue operator drains everything, and the "buy/sell-only" rule is software, not math. That's
custodial, and it's the load we're removing.

**The key reframe that makes all three possible:** stop protecting a *dangerous* key; issue a *powerless*
one. A plain Solana keypair can sign anything, so "only swap, never withdraw" can't be a property of the
key — it must be enforced by a **program**. The vault is that program. Once the agent's key can only ever
produce a swap that *returns value to the vault*, it is safe to hold on any CPU, Circuit needs to hold
nothing, and the funds answer only to the user's key.

**Net effect:** the entire off-box custody apparatus — signer, sealed seeds, master key, session tokens,
the epoch fence — is replaced by ~one Anchor program. Custody stops being a server you trust and becomes
code anyone can read.

---

## 2. Design principles

- **The chain is the enforcer, not Circuit.** Every fund-safety guarantee is a program invariant, not an
  off-chain policy. If the program can't prove it, we don't claim it.
- **Powerless delegate.** The agent holds only a `delegate` key that the program restricts to `trade`. It
  can churn the position; it can never remove value. So it's safe on an untrusted host, and losing/leaking
  it is low-stakes (bounded by caps, never a drain).
- **Owner is sovereign.** Only the `owner` key (the user's, never seen by Circuit) can withdraw, retarget,
  rotate the delegate, or close the vault.
- **Trade anything, prove the result.** We do not hardcode a venue. The `trade` instruction runs whatever
  swap the agent supplies, then asserts the *outcome* on the vault's own balances — value in, value out,
  nothing escaped. Route-agnostic by construction (Jupiter today, anything tomorrow).
- **Fail closed.** Any unmet invariant reverts the whole transaction. No partial, no "best effort."
- **Custody first, cleverness later.** Phase 1 proves the custody property (owner-only withdraw, delegate
  can't extract) before a single swap exists. On-chain Verified Intents is a later layer, not a dependency.

---

## 3. Architecture

### 3.1 The Vault account (PDA)

One vault per agent. Program-derived address, so the program signs for it (`invoke_signed`); no private
key exists for the vault itself.

```
seeds = [b"vault", owner, agent_seed]      // agent_seed = a per-agent id/nonce → many agents per owner
Vault {
  owner:            Pubkey,    // sole withdraw/admin authority (the user)
  delegate:         Pubkey,    // the agent's trading key — trade-only
  // policy (owner-set; the on-chain analogue of today's signer policy)
  max_trade_lamports: u64,     // cap per trade (SOL-notional, via wSOL leg)
  daily_limit_lamports: u64,   // rolling 24h cap
  allowed_mints:    Pubkey[]?,  // optional allowlist; empty = any mint
  min_out_bps_floor: u16,      // max slippage the delegate may accept (anti-grief)
  rule_commit:      [u8;32]?,   // optional: hash of the committed Verified-Intents rule (Phase 4)
  // accounting + safety
  day_start_ts:     i64,
  day_spent_lamports: u64,
  last_trade_ts:    i64,
  epoch:            u64,        // owner bumps to fence a stale delegate (optional)
  paused:           bool,       // owner kill-switch
  bump:             u8,
}
```

Funds live in accounts **owned by the vault PDA**: native SOL on the PDA (or a wSOL ATA), and an
Associated Token Account per token the vault holds. Because the PDA is the authority, only the program —
under its instruction rules — can move them.

### 3.2 Instructions

| Instruction | Signer | What it does / enforces |
|---|---|---|
| `init_vault(config)` | **owner** | Create the PDA, set delegate + policy. One-time. |
| `deposit` | anyone | Move SOL/tokens into the vault's accounts (or just transfer to its address; a helper handles wSOL/ATA creation). |
| **`trade(route, amount_in, min_out)`** | **delegate** | The core. Runs the swap via guarded CPI; asserts value stayed in the vault and caps/slippage held. §4. |
| `withdraw(amount, dest?)` | **owner** | Move SOL/tokens out to the owner (default) or an owner-named dest. The *only* exit. |
| `set_delegate(new)` | **owner** | Rotate or revoke the agent key (also bumps `epoch`). |
| `update_config(..)` | **owner** | Change caps / allowlist / rule / pause. |
| `close_vault` | **owner** | After draining, close accounts and reclaim rent. |

Note what's **absent**: there is no instruction the `delegate` can call that moves value out. The delegate
can call exactly one thing — `trade` — and `trade` cannot pay out. That's the whole guarantee, in the
shape of the API.

---

## 4. The `trade` instruction — the crux

This is ~80% of the engineering and all of the risk. It must let the agent swap **arbitrary** tokens
through **any** route while making extraction *impossible*. The technique is a **balance-delta guard**: we
don't trust the route, we verify the *result* on the vault's own accounts.

```
trade(route_data, accounts, amount_in, min_out):
  require !paused
  require signer == delegate                              // only the agent key
  require epoch matches                                    // optional fence

  // 1. policy
  require amount_in <= max_trade_lamports
  roll_day(); require day_spent + amount_in <= daily_limit
  require input_mint, output_mint ∈ allowed_mints (if set)
  require min_out >= quote * (1 - min_out_bps_floor)       // delegate can't accept a grief price

  // 2. snapshot — the vault's balances BEFORE
  before_in  = balance(vault_input_ata)
  before_out = balance(vault_output_ata)
  before_sol = lamports(vault)                             // minus expected fee budget

  // 3. snapshot the FULL state of every vault-owned account (not just balances — see ADR-0:
  //    route policy = ANY program, so the guard is the sole boundary and must catch authority
  //    grants, not only balance moves).
  for acct in vault_owned_accounts:
    snapshot[acct] = { amount, delegate, owner/close_authority, owner_program }

  // 4. execute the swap — invoke_signed with the vault PDA as authority. ANY program allowed
  //    (no CPI allowlist) — the guard below is what makes that safe.
  invoke_signed(route_program, accounts, route_data, &[vault_seeds])

  // 5. THE GUARD — assert value AND authority stayed in the vault
  // 5a. value
  require before_in - after_in  <= amount_in               // spent no more than authorized
  require after_out - before_out >= min_out                // received at least min_out  ← anti-theft line
  require every other vault ATA's amount unchanged          // only the declared input/output moved
  require lamports(vault) >= before_sol - max_fee          // SOL didn't walk out as "fees"
  // 5b. authority (REQUIRED because any program is allowed — catches the no-balance-change attacks)
  require every vault ATA.delegate == None (or unchanged)   // no `approve` granted → no future drain
  require every vault ATA.owner/close_authority == vault PDA // no `setAuthority` handoff
  require every vault account.owner_program unchanged        // not reassigned / closed out from under us
  require vault PDA still owned by THIS program

  // 6. account
  day_spent += (before_in - after_in); last_trade_ts = now
```

**Why this is safe, plainly:**
- The program **controls which accounts** the swap uses — it passes the vault's *own* input and output
  ATAs. The delegate cannot point the output at its own wallet; the program does.
- **Any swap program is allowed** (ADR-0), so there is *no* CPI allowlist — the **guard is the entire
  defense.** That's why §5b is mandatory: a pure balance check would miss `approve`/`setAuthority`
  (instructions that grant *future* control without moving a balance now). The guard re-validates the full
  post-state of every vault account — balances **and** delegate/authority/ownership — so the only thing the
  delegate can leave behind is "same accounts, same authorities, value swapped within caps."
- The **post-condition is the real lock:** output must increase by `min_out`, nothing else may move, and no
  authority may change. If anything else happened, the **entire transaction reverts.** Whatever ran between
  snapshot and check is irrelevant — if the vault isn't in exactly the shape a fair swap leaves it, nothing
  happened.

> **ADR-0 security note (any-program route policy):** allowing any CPI target maximizes flexibility (any
> DEX/router, today and future) but makes the guard the sole boundary and widens the audit surface. The
> §5b authority checks are non-negotiable under this policy. The adversarial test suite must explicitly
> include `approve`, `setAuthority`, `closeAccount`, and reassign attempts — not just balance drains.

So the delegate can do exactly one thing with the vault's money: **turn token A into a fair amount of token
B, inside the vault.** It cannot take A, cannot redirect B, cannot drain SOL. That is non-custodial trading
of arbitrary tokens, enforced by math.

**Residual (named honestly):** the delegate *can* still make *bad-but-real* trades — churn, or accept up to
`min_out_bps_floor` slippage — i.e. **grief**, not steal. Caps + the slippage floor bound it; **Phase 4
(on-chain Verified Intents) closes even this** by requiring each trade to match the owner's committed rule.

---

## 5. Security model

**Threat actors → outcome:**
- **The contributor host** (runs the agent, holds the delegate key): can trigger in-policy `trade`s; **can
  never withdraw, redirect, or drain.** Worst case: griefing within caps/slippage.
- **Circuit / the control plane:** holds **no keys**, has **no instruction** that moves user funds. Can
  schedule/stop agents; cannot touch money.
- **A breach of Circuit's servers:** nothing to steal — there are no keys and no privileged fund path.
- **The owner (user):** sovereign — withdraw, rotate, pause, close. The only one who can move value out.

**Invariants the program guarantees (and the tests assert):**
1. Only `owner` can reduce the vault's total value to an external account (`withdraw`).
2. `delegate` calling `trade` cannot reduce vault value beyond slippage (`after_out >= min_out`).
3. No instruction lets `delegate` set `owner`, `withdraw`, or `set_delegate`.
4. Caps (per-trade, daily) and the slippage floor hold on every `trade`.
5. A revoked/rotated delegate (epoch bump) can no longer trade.
6. Math is checked (no overflow/underflow); failure reverts.

**Best-practice guardrails:** Anchor account constraints (owner/PDA/signer checks, discriminators); CPI
target allowlist; snapshot-then-verify ordering; explicit `paused` kill-switch; upgrade authority held by
a multisig (and a path to making the program immutable post-audit).

---

## 6. Verified Intents, on-chain (Phase 4 — the integrity layer)

The [Verified Intents](VERIFIED_INTENTS.md) work already defines a committed decision **rule** + signed
**evidence** (prices, inference receipts). Today the off-box signer re-checks it. The vault can enforce it
**on-chain**, turning "the host can't forge a trade" from a server promise into a chain rule:

- The owner commits `rule_commit = hash(rule)` in the vault.
- `trade` additionally takes the rule inputs + evidence. Evidence signatures are verified with Solana's
  **Ed25519 program** (a sibling instruction in the same tx; the vault reads its verified result — the
  standard pattern, no expensive in-program crypto). The vault re-runs the rule (ported to Rust) and
  requires it to produce *this* trade.
- Result: the chain refuses any trade the owner's rule + authenticated data don't justify — closing the
  griefing residual from §4.

This is the strongest end state and it composes cleanly, but it is **not** a Phase-1 dependency: custody
(can't steal) ships first; integrity (can't even grief) layers on.

---

## 7. Off-chain changes (and what gets deleted)

The program shrinks the rest of the system:

- **Agent runtime (`@circuit/agent` / agentd):** instead of POSTing intents to the signer, the agent builds
  a `trade` instruction, signs it with its **local delegate key** (powerless), and submits to an RPC.
  `this.buy/sell` become "build + sign + send a `trade`." Paper mode unchanged (no chain).
- **The signer:** **deleted** for the vault path (kept only for legacy/paper during migration). Gone with
  it: sealed seeds, the master key, sessions, the epoch fence as custody machinery. Big subtraction.
- **Control plane:** still schedules/places agents and tracks liveness; **no longer provisions wallets or
  holds custody**. It records each agent's `vault` pubkey + `delegate`. Placement logic unchanged.
- **CLI (`circuit agent`):** `create` now (a) generates a delegate keypair for the agent, (b) has the
  **user sign `init_vault`** (owner = user's wallet, delegate = the agent key) and fund it; `withdraw`
  becomes the **owner-signed on-chain** withdraw; `export` is moot (the user already holds the owner key;
  the delegate is disposable). `agent owner`/caps map to `update_config`.
- **Delegate key handling:** generated per agent, lives with the agent on its host. Because it's powerless,
  this is fine; on reschedule it travels with the agent (or the owner rotates it). Leakage ≠ loss.

---

## 8. Environment specifics (Solana realities to get right)

These are the sharp edges that make this "a product" and not a demo:

- **Both token programs.** SPL Token *and* Token-2022 (CIRC is Token-2022; most memecoins are SPL). The
  vault must create/own ATAs and read balances under **both** programs. Token-2022 transfer-fee/hook
  extensions need handling (fee-on-transfer changes the balance-delta math — account for it or denylist
  hooked mints initially).
- **Wrapped SOL.** Jupiter trades wSOL, the vault holds native SOL. `trade` must wrap (create/sync a wSOL
  ATA) and unwrap around the swap, and the guard must treat wSOL↔SOL as same-value (not "value left").
- **Compute budget.** Swap CPI + balance checks (+ Ed25519/rule in Phase 4) can exceed the 200k CU
  default; request up to 1.4M CU. Keep the instruction lean.
- **Address-lookup tables.** Jupiter routes use ALTs and many accounts; the `trade` tx is a **v0
  (versioned)** transaction. The agent builds the route (Jupiter API → instructions), the program wraps it.
- **Jupiter CPI.** Use Jupiter's CPI-friendly path (shared-accounts route). This is the fiddly integration;
  prototype against devnet Jupiter or a mock AMM first, then wire mainnet-Jupiter semantics.
- **Rent.** Vault PDA + each ATA need rent-exemption (~0.002 SOL each), paid by the user at create/first
  trade. The program account rent (~1–3 SOL, **recoverable**) is the one-time deploy cost — **devnet is
  free**, mainnet later.
- **Fees + gas.** Each trade burns SOL fees + Jupiter platform fee; the vault funds these from its SOL. The
  guard's `max_fee` bound prevents "fees" being an exfiltration channel.

---

## 9. Build plan (devnet, phased — each phase ships tested)

Everything here is **free** (devnet SOL is airdropped). New Anchor workspace (`programs/agent-vault`),
reusing the toolchain already proven by `mesh_registry`.

| Phase | Deliverable | Proves |
|---|---|---|
| **0 — Scaffold** | Anchor workspace, CI, localnet test harness, this spec → ADRs | toolchain + shape |
| **1 — Custody core** | `init_vault`, `deposit`, owner `withdraw`, `set_delegate`, `close_vault` + tests | **the property**: owner controls; delegate has no path to funds |
| **2 — The trade guard** | `trade` against a **mock AMM**, full balance-delta guard | delegate can swap but **cannot extract** (attack tests: redirect output, drain input, wrong program, exceed cap → all revert) |
| **3 — Real swaps + policy** | Jupiter CPI (devnet), wSOL wrap/unwrap, Token-2022, caps/daily/slippage/allowlist | trades **any** real token, safely, within policy |
| **4 — Verified Intents on-chain** | rule_commit + Ed25519-verified evidence + rule re-run in `trade` | **can't even grief** — only rule-justified trades sign |
| **5 — Off-chain integration** | agent builds+signs `trade`; CLI `create`/`withdraw`; control-plane tracks vaults; signer retired (dev) | the system runs on the vault, not the signer |
| **6 — E2E devnet demo** | a live agent trading real devnet tokens, non-custodially, on a mesh CPU | the whole thesis, working, $0 spent |

**Testing standard (non-negotiable for fund code):** every phase ships an **adversarial** test suite — not
just "it works," but "the delegate *cannot* do X": redirect output, swap to its own ATA, exceed caps,
forge the owner, replay a revoked delegate, sneak a non-Jupiter CPI, fee-drain. Red-team the guard
explicitly. Localnet + devnet.

**Then, and only then:** professional audit → mainnet deploy (recoverable ~1–3 SOL) → retire the signer in
prod. Audit is the gate before *other people's* money; not needed for devnet or your own funds.

---

## 10. Decisions (ADR-0 — locked)

1. **Vault model: one vault PER AGENT.** ✅ Cleanest isolation, simplest accounting, smallest blast radius.
2. **Route policy: ANY program by default, with an OPTIONAL owner-set allowlist.** ✅ The guard enforces
   the full post-state invariant (§5b) regardless of route — so extraction is impossible either way. On
   top of that, `set_routes` lets a cautious owner restrict a vault to audited routers (e.g. Jupiter), so
   the guard isn't the *sole* boundary (defense in depth). Empty allowlist = any program (the default).
   *Resolution of the earlier any-program-only concern: the owner now chooses their risk posture.*
3. **Verified Intents on-chain: IN v1.** ✅ Phase 4 ships in the first build — the program enforces the
   committed rule + signed evidence, so the chain refuses even *griefing* (off-rule) trades, not just theft.
4. **Delegate key:** host-held + owner-rotatable (it's powerless, so leakage ≠ loss).
5. **Upgrade authority:** multisig at deploy; path to immutable post-audit.
6. **Repo:** dedicated `circuit-agent-vault` (independently-auditable artifact) with the program + the
   off-chain client.

Open items still to settle during the build: exact wSOL wrap/unwrap flow, Token-2022 fee-extension
handling, and the Rust port of the rule evaluator for Phase 4.

---

## 11. The payoff

When Phase 6 lands on devnet you will have, working and provable: **users trade any token, autonomously, on
your CPU mesh, with Circuit holding zero keys and zero ability to touch their funds — and the custodial
signer deleted.** The trust problem you flagged stops being "don't breach our server" and becomes "read our
~400 KB of audited code." That is the product.
