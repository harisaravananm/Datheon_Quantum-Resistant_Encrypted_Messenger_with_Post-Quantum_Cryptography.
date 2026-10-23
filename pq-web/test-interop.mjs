// Decrypts a message produced by the Rust ratchet: node test-interop.mjs "<n> <nonce_hex> <ct_hex>"
import { Session, unhex } from './src/crypto.js';
const [n, nonce, ct] = process.argv[2].split(' ');
const bob = await Session.create(new Uint8Array(32).fill(42), false);
const r = await bob.decrypt({ n: +n, nonce: unhex(nonce), ct: unhex(ct) });
const text = new TextDecoder().decode(r.pt);
console.log(text === 'hello from rust' ? 'PASS rust -> js interop: ' + text : 'FAIL ' + text);
