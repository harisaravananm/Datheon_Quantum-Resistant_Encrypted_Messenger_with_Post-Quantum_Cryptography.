import { Client } from './client.js';

const $ = (s) => document.querySelector(s);
const el = (t, c, x) => { const e = document.createElement(t); if (c) e.className = c; if (x !== undefined) e.textContent = x; return e; };
const store = { get: (k) => { try { return JSON.parse(localStorage.getItem('pqm:' + k)); } catch { return null; } }, set: (k, v) => localStorage.setItem('pqm:' + k, JSON.stringify(v)) };

let client, current = null;
const chats = new Map(); // peer -> [{dir,text,meta,tampered?,bad?}]
const log = (peer) => { if (!chats.has(peer)) chats.set(peer, []); return chats.get(peer); };

function kv(box, rows) { box.replaceChildren(); for (const [k, v] of rows) { const r = el('div', 'kv'); r.append(el('span', 'k', k), el('span', 'v', String(v))); box.append(r); } }

function renderPeers() {
  const box = $('#peers'); box.replaceChildren();
  for (const p of chats.keys()) { const b = el('button', 'peer' + (p === current ? ' on' : ''), p); b.onclick = () => { current = p; renderAll(); }; box.append(b); }
}
function renderChat() {
  const box = $('#msgs'); box.replaceChildren();
  $('#chatTitle').textContent = current ? 'Chat with ' + current : 'Pick or start a chat';
  if (!current) return;
  for (const m of log(current)) {
    const b = el('div', 'bubble ' + m.dir + (m.bad ? ' bad' : ''), m.text);
    if (m.tampered) b.append(el('small', '', ' (sent tampered)'));
    if (m.meta) b.onclick = () => showMeta(m);
    box.append(b);
  }
  box.scrollTop = box.scrollHeight;
  const info = client.peer(current).info;
  kv($('#session'), info ? [['role', info.role], ['key exchange', info.kem], ['public key', info.ekBytes + ' B'], ['KEM ciphertext', info.kemCtBytes + ' B'],
    ['shared secret', info.sharedSecretBytes * 8 + ' bits (fp ' + info.sharedSecretFp + ')'], ['safety number', info.safety]] : [['status', 'no session yet: created on first message']]);
}
function showMeta(m) {
  const x = m.meta;
  kv($('#meta'), [['direction', m.dir === 'out' ? 'sent' : 'received'], ['cipher', x.cipher], ['message #', x.n], ['IV / nonce (96-bit)', x.nonce],
    ['auth tag (128-bit)', x.tag], ['ciphertext', x.ctBytes + ' B  ' + x.ctPreview + '…'], ['on the wire', x.wireBytes + ' B (hex inside JSON)'],
    ['AAD', x.aad], ['message key fp', x.mkFp + '  (used once, then discarded)'], ['next chain key fp', x.ckFp], ['root key fp', x.rootFp]]);
}
function renderAll() { renderPeers(); renderChat(); }

function wire(e) {
  const box = $('#wire'); let f = e.frame;
  try { const o = JSON.parse(f); if (o.payload && o.payload.length > 48) o.payload = o.payload.slice(0, 48) + '…(' + o.payload.length + ' hex chars)'; if (o.ek) o.ek = o.ek.slice(0, 24) + '…(public key)'; f = JSON.stringify(o); } catch {}
  const d = el('div', 'w ' + e.dir, (e.dir === 'out' ? '→ ' : '← ') + f);
  box.prepend(d); while (box.children.length > 40) box.lastChild.remove();
}
function onEvent(e) {
  if (e.type === 'wire') return wire(e);
  if (e.type === 'sent') { log(e.to).push({ dir: 'out', text: e.text, meta: e.meta, tampered: e.tampered }); showMeta({ dir: 'out', meta: e.meta }); }
  if (e.type === 'message') { log(e.from).push({ dir: 'in', text: e.text, meta: e.meta }); if (!current) current = e.from; showMeta({ dir: 'in', meta: e.meta }); }
  if (e.type === 'security') { const who = (e.text.match(/^from (\S+):/) || [])[1]; const t = '⚠ ' + e.text; if (who) log(who).push({ dir: 'in', text: t, bad: true }); else if (current) log(current).push({ dir: 'in', text: t, bad: true }); }
  if (e.type === 'closed') $('#status').textContent = 'disconnected';
  renderAll();
}

$('#connect').onclick = async () => {
  const user = $('#user').value.trim(), url = $('#url').value.trim();
  $('#err').textContent = '';
  try {
    client = new Client({ url, user, store, onEvent });
    await client.connect();
  } catch (e) { $('#err').textContent = e.message === 'name_taken' ? 'Name already registered with a different key (clear site data or pick a new name).' : e.message; return; }
  $('#login').hidden = true; $('#app').hidden = false; $('#status').textContent = 'connected as ' + user;
  renderAll();
};
$('#start').onclick = () => { const p = $('#peerName').value.trim(); if (p) { current = p; log(p); $('#peerName').value = ''; renderAll(); } };
async function doSend(tamper) {
  const t = $('#text').value; if (!t) return;
  if (!client || !current) { $('#chatTitle').textContent = 'Type a username under Chats and press Start first'; return; }
  $('#text').value = '';
  try { await client.send(current, t, { tamper }); } catch (e) { log(current).push({ dir: 'in', text: '⚠ ' + e.message, bad: true }); renderAll(); }
}
$('#send').onclick = () => doSend(false);
$('#tamper').onclick = () => doSend(true);
$('#text').onkeydown = (e) => { if (e.key === 'Enter') doSend(false); };
