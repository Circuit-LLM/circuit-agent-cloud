// Zero-dependency Solana-compatible crypto for the signer.
//
// Solana keypairs ARE Ed25519, and Node ≥18 ships native Ed25519 + AES-GCM —
// so the signer holds real, fundable Solana addresses and produces real
// signatures with no @solana/web3.js (the whole package stays dependency-free).
//
//   newKeypair()            -> { seed, priv, pubkey, address }
//   fromSeed(seed)          -> same, deterministic from a 32-byte seed
//   sign(priv, msg)         -> 64-byte Ed25519 signature (Buffer)
//   verify(pubkey, msg, sig)-> boolean
//   seal/open(key, ...)     -> AES-256-GCM at-rest encryption for the seed
//   base58(buf)             -> Solana address encoding
//
// The 64-byte Solana secret key (seed‖pubkey) is reconstructable from the seed,
// so wiring a live on-chain submitter later is a drop-in — see signer/server.js.
import crypto from 'node:crypto';

// Fixed DER framings for Ed25519 (RFC 8410). The key bytes are the tail.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex'); // 16B + 32B seed
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex'); //          12B + 32B pubkey

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58(buf) {
  const bytes = Uint8Array.from(buf);
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = []; // big-endian base-58 of the non-zero portion
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = '1'.repeat(zeros); // one '1' per leading zero byte
  for (let k = digits.length - 1; k >= 0; k--) out += B58[digits[k]];
  return out;
}

export function base58decode(str) {
  const map = B58_MAP;
  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') zeros++;
  const bytes = [];
  for (let i = zeros; i < str.length; i++) {
    let carry = map[str[i]];
    if (carry === undefined) throw new Error(`invalid base58 char '${str[i]}'`);
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  const out = Buffer.alloc(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + bytes.length - 1 - i] = bytes[i];
  return out;
}
const B58_MAP = Object.fromEntries([...B58].map((ch, i) => [ch, i]));

export function fromSeed(seed) {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
  const spki = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
  const pubkey = Buffer.from(spki.subarray(spki.length - 32));
  return { seed: Buffer.from(seed), priv, pubkey, address: base58(pubkey) };
}

export function newKeypair() {
  return fromSeed(crypto.randomBytes(32));
}

export function sign(priv, msg) {
  return crypto.sign(null, Buffer.from(msg), priv); // null algo == Ed25519
}

export function verify(pubkey, msg, sig) {
  const pub = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(pubkey)]), format: 'der', type: 'spki' });
  return crypto.verify(null, Buffer.from(msg), pub, Buffer.from(sig));
}

// AES-256-GCM. masterKey = 32 raw bytes. Returns/takes hex fields.
export function seal(masterKey, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), ct: ct.toString('hex') };
}

export function open(masterKey, rec) {
  const d = crypto.createDecipheriv('aes-256-gcm', masterKey, Buffer.from(rec.iv, 'hex'));
  d.setAuthTag(Buffer.from(rec.tag, 'hex'));
  return Buffer.concat([d.update(Buffer.from(rec.ct, 'hex')), d.final()]);
}

export const sha256hex = (s) => crypto.createHash('sha256').update(s).digest('hex');
export const randomToken = () => crypto.randomBytes(24).toString('base64url');
