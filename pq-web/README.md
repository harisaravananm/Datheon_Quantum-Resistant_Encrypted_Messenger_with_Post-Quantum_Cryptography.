# pq-web: browser client (Milestone 4)

**Use it (no install):** start the relay, then open `dist/index.html` in two tabs. Use different usernames, start a chat from one to the other.

**Rebuild / tests (needs Node 18+):**
```
npm install
node build.mjs            # regenerates dist/index.html
node test-e2e.mjs         # needs relay on 127.0.0.1:9001
node test-interop.mjs "<n> <nonce_hex> <ct_hex>"   # from: cargo run --example vector (in pq-kem)
```
Docs: `docs/ARCHITECTURE.md`, `docs/WIRESHARK.md`.
