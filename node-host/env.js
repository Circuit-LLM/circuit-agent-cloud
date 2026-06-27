// node-host/env.js — the curated environment a hosted workload receives.
//
// SECURITY (AGENT_BUNDLES.md §5.1 / phase B0): a hosted workload must NEVER inherit the operator's
// whole process.env — that would leak the operator's own keys/tokens to every agent it hosts. Instead
// it gets a curated allowlist: a process minimum + the Circuit identity/session vars + only the specific
// endpoints/secrets the workload legitimately needs, gated by trust level:
//
//   trusted   (built-in agentd / circuit-agent) → base + endpoints + first-party secrets
//   untrusted (a user bundle, B1+)              → base + endpoints (URLs only), NEVER secrets
import path from 'node:path';

// Service-endpoint URLs with NO embedded credential (agents authenticate via x402/session). Safe to
// forward at any trust level.
export const ENDPOINT_ENV = ['CIRCUIT_API_URL', 'GATEWAY_URL', 'PRICE_FEED_URL', 'CIRCUIT_INFERENCE_URL'];

// Endpoint URLs that MAY embed a credential (e.g. a keyed Helius RPC URL). Forwarded verbatim ONLY to
// trusted built-ins. For an UNTRUSTED bundle the keyed value is withheld; if the operator set a keyless/
// proxied CIRCUIT_PUBLIC_RPC_URL it is substituted as CIRCUIT_RPC_URL, otherwise RPC is simply absent.
export const CREDENTIALED_ENDPOINT_ENV = ['CIRCUIT_RPC_URL'];

// First-party workload secrets — forwarded ONLY to trusted built-in workloads, never to a bundle.
export const SECRET_ENV = ['AGENT_KEYPAIR', 'CIRCUIT_SETUP_KEYPAIR', 'CIRCUIT_INTERNAL_KEY',
  'JUPITER_API_KEY', 'OPENROUTER_API_KEY', 'TELEGRAM_BOT_TOKEN'];

// Cosmetic passthroughs — safe at any trust level.
const COSMETIC_ENV = ['FORCE_COLOR'];

// Identity/session vars the host sets itself — a spec.env can never shadow these.
const PROTECTED = [/^CIRCUIT_AGENT_/, /^CIRCUIT_SIGNER_/];

// Process-influencing vars a spec.env must NEVER set — they steer the runtime itself (code-load /
// linker control). Blocked at every trust level; spec.env is for app config, not process tuning.
const DANGEROUS_ENV = [/^NODE_OPTIONS$/, /^LD_/, /^BASH_ENV$/, /^npm_config_/i, /^DYLD_/];

/**
 * Build the curated env for a hosted workload.
 * @param {object} a        the start assignment ({ name, spec, signer })
 * @param {string} dir      the agent's writable data dir
 * @param {object} [srcEnv] source env to draw allowlisted vars from (default process.env)
 * @returns {Record<string,string>} the exact, curated env the workload will run with
 */
export function buildAgentEnv(a, dir, srcEnv = process.env) {
  const spec = a?.spec || {};
  const signer = a?.signer;
  // A built-in workload is first-party/trusted; a bundle (B1+) is untrusted and gets no secrets.
  // The bundle marker can be top-level (the start assignment) or in spec (the stored record).
  const trusted = !(a?.bundle || spec.bundle);

  // 1. process minimum — HOME/TMPDIR confined to the agent's own dir, nothing inherited wholesale
  const env = {
    PATH: srcEnv.PATH || '/usr/local/bin:/usr/bin:/bin',
    HOME: dir,
    TMPDIR: path.join(dir, 'tmp'),
    LANG: srcEnv.LANG || 'C.UTF-8',
    TZ: srcEnv.TZ || 'UTC',
    CIRCUIT_AGENT_DATA_DIR: dir,
    AGENT_NAME: a?.name || '',
  };

  // 2. off-box custody: the scoped, rotating SESSION TOKEN — never the signing key
  if (signer) {
    env.CIRCUIT_SIGNER_URL = signer.url;
    env.CIRCUIT_AGENT_ID = signer.agentId;
    env.CIRCUIT_AGENT_EPOCH = String(signer.epoch);
    env.CIRCUIT_AGENT_SESSION = signer.token;
    env.CIRCUIT_AGENT_ADDRESS = signer.address || '';
    env.CIRCUIT_AGENT_PAPER = signer.paper === false ? '0' : '1';
  }

  // 3. allowlisted passthrough — safe endpoints for everyone; credentialed endpoints + first-party
  //    secrets only for trusted built-ins. An untrusted bundle NEVER receives a keyed URL or a secret.
  const allow = [...ENDPOINT_ENV, ...COSMETIC_ENV, ...(trusted ? [...CREDENTIALED_ENDPOINT_ENV, ...SECRET_ENV] : [])];
  for (const k of allow) if (srcEnv[k] != null) env[k] = srcEnv[k];
  if (!trusted && srcEnv.CIRCUIT_PUBLIC_RPC_URL) env.CIRCUIT_RPC_URL = srcEnv.CIRCUIT_PUBLIC_RPC_URL; // keyless RPC substitute

  // 4. agent-declared env (spec.env), validated: can't shadow an identity var, smuggle a secret-named
  //    var (untrusted), or set a process-influencing var (any trust level)
  for (const [k, v] of Object.entries(spec.env || {})) {
    if (PROTECTED.some((re) => re.test(k))) continue;
    if (DANGEROUS_ENV.some((re) => re.test(k))) continue;
    if (!trusted && (SECRET_ENV.includes(k) || CREDENTIALED_ENDPOINT_ENV.includes(k))) continue;
    env[k] = String(v);
  }
  return env;
}
