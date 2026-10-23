// Run with the relay on 127.0.0.1:9001.  node test-e2e.mjs
import net from 'node:net';
import WebSocket from 'ws';
import { Client } from './src/client.js';
import { hex } from './src/crypto.js';

const RELAY = 9001, PROXY = 9002;
let toServer = Buffer.alloc(0), toClient = Buffer.alloc(0);
const proxy = net.createServer((c) => {
  const s = net.connect(RELAY, '127.0.0.1');
  c.on('data', (d) => { toServer = Buffer.concat([toServer, d]); s.write(d); });
  s.on('data', (d) => { toClient = Buffer.concat([toClient, d]); c.write(d); });
  c.on('close', () => s.destroy()); s.on('close', () => c.destroy()); c.on('error', () => {}); s.on('error', () => {});
}).listen(PROXY);

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let fails = 0;
const check = (name, ok) => { console.log((ok ? 'PASS ' : 'FAIL ') + name); if (!ok) fails++; };
const mk = (user, log) => new Client({ url: `ws://127.0.0.1:${PROXY}`, user: user + Date.now() % 100000, WS: WebSocket, onEvent: (e) => log.push(e) });

const la = [], lb = [];
const alice = mk('alice', la), bob = mk('bob', lb);
await alice.connect(); await bob.connect();

const SECRET = 'TOP-SECRET-PLAINTEXT-4242';
await alice.send(bob.user, SECRET);
await alice.send(bob.user, 'second');
await wait(400);
await bob.send(alice.user, 'reply from bob');
await wait(400);

const got = lb.filter((e) => e.type === 'message').map((e) => e.text);
check('bob decrypts both messages in order', got[0] === SECRET && got[1] === 'second');
check('alice decrypts bob reply', la.some((e) => e.type === 'message' && e.text === 'reply from bob'));
const sa = la.find((e) => e.type === 'session').info, sb = lb.find((e) => e.type === 'session').info;
check('both sides derive same shared-secret fingerprint', sa.sharedSecretFp === sb.sharedSecretFp);
check('both sides show same safety number', sa.safety === sb.safety);
check('ML-KEM-768 sizes (ek 1184, ct 1088, ss 32)', sa.ekBytes === 1184 && sa.kemCtBytes === 1088 && sa.sharedSecretBytes === 32);

// Tamper: receiver must reject, then continue normally
await alice.send(bob.user, 'tampered one', { tamper: true });
await wait(300);
check('tampered message rejected by MAC', lb.some((e) => e.type === 'security' && /MAC verification failed/.test(e.text)));

// Wire capture: plaintext must not appear (server->client bytes are unmasked; client->server are masked, so also check decoded frames)
const wireFrames = [...la, ...lb].filter((e) => e.type === 'wire').map((e) => e.frame).join('\n');
const needles = [SECRET, 'second', 'reply from bob'];
const inBytes = (buf, n) => buf.includes(Buffer.from(n)) || buf.toString('latin1').includes(hex(Buffer.from(n)));
check('no plaintext in raw bytes relay->client', needles.every((n) => !inBytes(toClient, n)));
check('no plaintext in raw bytes client->relay', needles.every((n) => !inBytes(toServer, n)));
check('no plaintext in decoded WebSocket frames', needles.every((n) => !wireFrames.includes(n) && !wireFrames.includes(hex(Buffer.from(n)))));

// Negative control: a deliberately unencrypted payload IS detected, so the checks above are not vacuous
alice.ws.send(JSON.stringify({ type: 'send', to: bob.user, id: 'ctl1', payload: hex(Buffer.from('CONTROL-PLAINTEXT')) }));
await wait(300);
check('negative control: unencrypted payload is detected on the wire', inBytes(toClient, 'CONTROL-PLAINTEXT'));

console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED');
alice.close(); bob.close(); proxy.close(); process.exit(fails ? 1 : 0);
