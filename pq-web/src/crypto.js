// Wire-compatible JS port of the Rust ratchet (pq-kem/src/lib.rs) + ML-KEM-768 via @noble/post-quantum.
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

const subtle = globalThis.crypto.subtle;
const te = new TextEncoder();
export const kem = ml_kem768;
export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
export const unhex = (s) => Uint8Array.from(s.match(/../g) || [], (h) => parseInt(h, 16));
export const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
export const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
export const sha256 = async (b) => new Uint8Array(await subtle.digest('SHA-256', b));
export const fp = async (b) => hex((await sha256(b)).slice(0, 4)); // short fingerprint, never the key itself

async function hmac(key, tag) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, Uint8Array.of(tag)));
}
async function kdfRoot(rk, input) {
  const k = await subtle.importKey('raw', input, 'HKDF', false, ['deriveBits']);
  const out = new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: rk, info: te.encode('pq-messenger/root') }, k, 768));
  return [out.slice(0, 32), out.slice(32, 64), out.slice(64)];
}
const be32 = (n) => Uint8Array.of(n >>> 24, n >>> 16, n >>> 8, n);

export class Session {
  static async create(shared, initiator) {
    const s = new Session(); s.initiator = initiator;
    const [root, a2b, b2a] = await kdfRoot(new Uint8Array(32), shared);
    s.root = root; [s.sendCk, s.recvCk] = initiator ? [a2b, b2a] : [b2a, a2b]; s.sendN = 0; s.recvN = 0;
    return s;
  }
  async encrypt(plaintext) {
    const mk = await hmac(this.sendCk, 1);
    this.sendCk = await hmac(this.sendCk, 2);
    const n = this.sendN++;
    const nonce = rand(12);
    const key = await subtle.importKey('raw', mk, 'AES-GCM', false, ['encrypt']);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: be32(n), tagLength: 128 }, key, plaintext));
    return { n, nonce, ct, mkFp: await fp(mk), ckFp: await fp(this.sendCk), rootFp: await fp(this.root) };
  }
  async decrypt({ n, nonce, ct }) {
    if (n !== this.recvN) throw new Error('out-of-order or replayed message (n=' + n + ', expected ' + this.recvN + ')');
    const mk = await hmac(this.recvCk, 1);
    const key = await subtle.importKey('raw', mk, 'AES-GCM', false, ['decrypt']);
    let pt;
    try { pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: be32(n), tagLength: 128 }, key, ct)); }
    catch { throw new Error('MAC verification failed: message rejected'); }
    this.recvCk = await hmac(this.recvCk, 2); // advance only after a valid tag
    this.recvN++;
    return { pt, mkFp: await fp(mk), ckFp: await fp(this.recvCk), rootFp: await fp(this.root) };
  }
}

// Wire formats (hex-encoded by the client before going into the relay's opaque `payload`)
export const packInit = (kemCt) => cat(Uint8Array.of(1), kemCt);               // 0x01 || ML-KEM ct (1088 B)
export const packMsg = (m) => cat(Uint8Array.of(2), be32(m.n), m.nonce, m.ct);  // 0x02 || n || nonce(12) || ct||tag
export function unpack(b) {
  if (b[0] === 1) return { type: 'init', kemCt: b.slice(1) };
  if (b[0] === 2 && b.length >= 1 + 4 + 12 + 16) return { type: 'msg', n: ((b[1] << 24) | (b[2] << 16) | (b[3] << 8) | b[4]) >>> 0, nonce: b.slice(5, 17), ct: b.slice(17) };
  return { type: 'unknown' };
}

// Safety number: both parties compute it from the two public keys and compare out-of-band (defeats a key-swapping relay).
export async function safetyNumber(ekA, ekB) {
  const [x, y] = hex(ekA) < hex(ekB) ? [ekA, ekB] : [ekB, ekA];
  const h = await sha256(cat(te.encode('pq-messenger/safety'), x, y));
  const digits = Array.from(h.slice(0, 15), (v) => String(v % 100).padStart(2, '0')); // 15 groups of 2 digits
  return digits.join('').match(/.{5}/g).join(' ');
}
