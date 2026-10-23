// DOM-free protocol client: used by the web UI and by the Node end-to-end test.
import { kem, hex, unhex, rand, cat, fp, Session, packInit, packMsg, unpack, safetyNumber } from './crypto.js';

const td = new TextDecoder(), te = new TextEncoder();
const memStore = () => { const m = new Map(); return { get: (k) => m.get(k), set: (k, v) => m.set(k, v) }; };

export class Client {
  constructor({ url, user, WS = globalThis.WebSocket, store = memStore(), onEvent = () => {} }) {
    Object.assign(this, { url, user, WS, store, emit: onEvent });
    this.peers = new Map(); this.waiters = []; this.registered = null; this.q = Promise.resolve(); this.sq = Promise.resolve();
  }
  async connect() {
    const saved = this.store.get('keys:' + this.user);
    if (saved) { this.ek = unhex(saved.ek); this.dk = unhex(saved.dk); }
    else { const k = kem.keygen(); this.ek = k.publicKey; this.dk = k.secretKey; this.store.set('keys:' + this.user, { ek: hex(this.ek), dk: hex(this.dk) }); }
    this.ws = new this.WS(this.url);
    this.ws.addEventListener('message', (e) => this.#onFrame(String(e.data)));
    this.ws.addEventListener('close', () => this.emit({ type: 'closed' }));
    await new Promise((res, rej) => { this.ws.addEventListener('open', res); this.ws.addEventListener('error', () => rej(new Error('cannot reach relay'))); });
    const reg = new Promise((res, rej) => { this.registered = { res, rej }; });
    this.#out({ type: 'register', user: this.user, ek: hex(this.ek) });
    return reg;
  }
  close() { this.ws.close(); }
  #out(o) { const s = JSON.stringify(o); this.emit({ type: 'wire', dir: 'out', frame: s }); this.ws.send(s); }
  #lookup(user) { return new Promise((res, rej) => { this.waiters.push({ user, res, rej }); this.#out({ type: 'lookup', user }); }); }
  peer(name) { if (!this.peers.has(name)) this.peers.set(name, { session: null }); return this.peers.get(name); }

  async #startSession(name) {
    const p = this.peer(name);
    const ekHex = await this.#lookup(name);
    const peerEk = unhex(ekHex);
    const { cipherText, sharedSecret } = kem.encapsulate(peerEk);
    p.session = await Session.create(sharedSecret, true);
    p.info = await this.#sessionInfo(name, peerEk, cipherText, sharedSecret, 'initiator');
    this.emit({ type: 'session', peer: name, info: p.info });
    this.#out({ type: 'send', to: name, id: hex(rand(16)), payload: hex(packInit(cipherText)) });
  }
  async #sessionInfo(name, peerEk, kemCt, ss, role) {
    return { role, kem: 'ML-KEM-768 (FIPS 203)', ekBytes: peerEk.length, kemCtBytes: kemCt.length, sharedSecretBytes: ss.length,
      sharedSecretFp: await fp(ss), safety: await safetyNumber(this.ek, peerEk) };
  }
  send(name, text, opts) { return (this.sq = this.sq.catch(() => {}).then(() => this.#send(name, text, opts))); }
  async #send(name, text, { tamper = false } = {}) {
    const p = this.peer(name);
    if (!p.session) await this.#startSession(name);
    const m = await p.session.encrypt(te.encode(text));
    if (tamper) m.ct[0] ^= 1; // demo: corrupt in transit; receiver must reject
    const wire = packMsg(m);
    this.#out({ type: 'send', to: name, id: hex(rand(16)), payload: hex(wire) });
    this.emit({ type: 'sent', to: name, text, tampered: tamper, meta: this.#meta(m, wire) });
  }
  #meta(m, wire) {
    return { n: m.n, nonce: hex(m.nonce), tag: hex(m.ct.slice(-16)), ctPreview: hex(m.ct.slice(0, 24)), ctBytes: m.ct.length, wireBytes: wire.length,
      cipher: 'AES-256-GCM', aad: 'message counter n (4 B, big-endian)', mkFp: m.mkFp, ckFp: m.ckFp, rootFp: m.rootFp };
  }
  async #onFrame(s) {
    this.emit({ type: 'wire', dir: 'in', frame: s });
    let f; try { f = JSON.parse(s); } catch { return; }
    if (f.type === 'registered') return this.registered?.res(f);
    if (f.type === 'key') { const i = this.waiters.findIndex((w) => w.user === f.user); if (i >= 0) this.waiters.splice(i, 1)[0].res(f.ek); return; }
    if (f.type === 'error') {
      if (this.registered) { this.registered.rej(new Error(f.reason)); this.registered = null; return; }
      if (f.reason === 'unknown_user' && this.waiters.length) return this.waiters.shift().rej(new Error('unknown user'));
      return this.emit({ type: 'security', level: 'warn', text: 'relay: ' + f.reason });
    }
    if (f.type === 'msg') return (this.q = this.q.then(() => this.#onMsg(f.from, f.payload))); // strictly in order
  }
  async #onMsg(from, payload) {
    const p = this.peer(from), u = unpack(unhex(payload));
    try {
      if (u.type === 'init') {
        if (p.session?.initiator && this.user < from) return; // simultaneous start: lower name stays initiator
        const ss = kem.decapsulate(u.kemCt, this.dk);
        p.session = await Session.create(ss, false);
        const peerEk = unhex(await this.#lookup(from));
        p.info = await this.#sessionInfo(from, peerEk, u.kemCt, ss, 'responder');
        this.emit({ type: 'session', peer: from, info: p.info });
      } else if (u.type === 'msg') {
        if (!p.session) throw new Error('no session with ' + from);
        const r = await p.session.decrypt(u);
        this.emit({ type: 'message', from, text: td.decode(r.pt), meta: this.#meta({ ...u, ...r }, unhex(payload)) });
      }
    } catch (e) { this.emit({ type: 'security', level: 'bad', text: 'from ' + from + ': ' + e.message }); }
  }
}
