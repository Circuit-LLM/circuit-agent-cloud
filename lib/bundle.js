// lib/bundle.js — content-addressed agent bundles (AGENT_BUNDLES.md §2, phase B1).
//
// A bundle is a gzipped tarball of a built agent. Its sha256 IS its identity, so a node runs exactly
// the bytes that were published and a reschedule pulls the same bytes. A signed MANIFEST binds the
// bytes (sha256), the target agentId, and the entry to a publisher key — and at bind time the control
// plane checks that publisher == the agent's owner (so "signed" means "signed by someone allowed").
//
//   createBundle({ dir, agentId, entry, sdk, priv, publisherPubkey }) -> { bytes, sha256, manifest }
//   verifyBundle(bytes, manifest, { expectedOwner })                  -> { ok, code }
//   unpackTo(bytes, destDir)                                          -> entry path on disk
//
// B1 supports runtime 'node' (a tarball) only; 'oci' is B2.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { sign, verify, base58, base58decode, sha256hex } from './ed25519.js';

export const BUNDLE_SCHEMA = 1;

// The canonical bytes a publisher signs: the fields they commit to, in fixed (sorted-key) order. This
// MUST stay byte-identical to circuit-cli/src/services/bundle.js. publisherPubkey is NOT signed (the sig
// is verified *against* it; substituting it invalidates the sig) and the owner-binding ties that key to
// the owner. egress + resources ARE signed — the node uses them to set the allowlist + resource cap, so
// they must not be mutable on a still-valid signature.
export function canonResources(r) {
  return r ? { maxCpu: r.maxCpu ?? null, maxMemoryMb: r.maxMemoryMb ?? null } : null;
}
export function manifestSigningBytes(m) {
  const canon = {
    agentId: m.agentId,
    egress: Array.isArray(m.egress) ? [...m.egress].sort() : [],
    entry: m.entry,
    resources: canonResources(m.resources),
    runtime: m.runtime,
    schema: BUNDLE_SCHEMA,
    sdk: m.sdk ?? null,
    sha256: m.sha256,
  };
  return Buffer.from(JSON.stringify(canon));
}

export function signManifest(m, priv) {
  return base58(sign(priv, manifestSigningBytes(m)));
}

export function verifyManifest(m) {
  if (!m || !m.sig || !m.publisherPubkey) return false;
  try {
    return verify(base58decode(m.publisherPubkey), manifestSigningBytes(m), base58decode(m.sig));
  } catch {
    return false;
  }
}

// Pack a directory's contents into a gzipped tarball (deterministic metadata; gzip framing aside).
export function packDir(dir) {
  const tmp = path.join(os.tmpdir(), `cbundle-${crypto.randomBytes(6).toString('hex')}.tgz`);
  try {
    execFileSync('tar', ['--sort=name', '--owner=0', '--group=0', '--numeric-owner', '--mtime=@0',
      '-czf', tmp, '-C', dir, '.'], { stdio: 'pipe' });
    const bytes = fs.readFileSync(tmp);
    return { bytes, sha256: sha256hex(bytes) };
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

// Unpack verified bytes into destDir. Caller MUST verify the sha256 first (verifyBundle).
export function unpackTo(bytes, destDir) {
  fs.mkdirSync(destDir, { recursive: true });
  const tmp = path.join(os.tmpdir(), `cbundle-${crypto.randomBytes(6).toString('hex')}.tgz`);
  try {
    fs.writeFileSync(tmp, bytes);
    // refuse path-escaping members; GNU tar strips a leading '/' and we also forbid '..'
    execFileSync('tar', ['--no-same-owner', '-xzf', tmp, '-C', destDir], { stdio: 'pipe' });
  } finally {
    fs.rmSync(tmp, { force: true });
  }
  return destDir;
}

// An entry must be a plain filename inside the bundle — never a path component that escapes it.
export function isSafeEntry(entry) {
  return typeof entry === 'string' && /^[\w][\w.-]*$/.test(entry) && entry !== '.' && entry !== '..' && !entry.includes('/');
}

export function createBundle({ dir, agentId, runtime = 'node', entry = 'agent.js', sdk = null, egress = [], resources = null, priv, publisherPubkey }) {
  if (runtime !== 'node' && runtime !== 'oci') throw new Error(`unknown runtime '${runtime}'`);
  if (!isSafeEntry(entry)) throw new Error(`unsafe entry '${entry}'`);
  if (!fs.existsSync(path.join(dir, entry))) throw new Error(`entry '${entry}' not found in ${dir}`);
  const { bytes, sha256 } = packDir(dir);
  const manifest = { schema: BUNDLE_SCHEMA, agentId, runtime, entry, sdk, egress, resources, sha256, publisherPubkey };
  manifest.sig = signManifest(manifest, priv);
  return { bytes, sha256, manifest };
}

// The checks before any code runs: bytes hash to the claimed sha256, the manifest is validly signed,
// (when given) the publisher is the agent's owner and the manifest targets this agent, and the entry is
// a safe in-bundle filename. No unverified bytes ever execute, and a "valid" manifest can't steer
// execution outside the verified tree.
export function verifyBundle(bytes, manifest, { expectedOwner, expectedAgentId } = {}) {
  if (sha256hex(bytes) !== manifest.sha256) return { ok: false, code: 'sha256-mismatch' };
  if (!verifyManifest(manifest)) return { ok: false, code: 'bad-manifest-sig' };
  if (expectedOwner && manifest.publisherPubkey !== expectedOwner) return { ok: false, code: 'publisher-not-owner' };
  if (expectedAgentId && manifest.agentId !== expectedAgentId) return { ok: false, code: 'agent-id-mismatch' };
  if (!isSafeEntry(manifest.entry)) return { ok: false, code: 'bad-entry' };
  return { ok: true };
}
