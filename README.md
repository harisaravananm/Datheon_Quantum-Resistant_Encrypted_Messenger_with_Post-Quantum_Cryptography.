<h1 align="center">🛡️ Quantum-Resistant Encrypted Messenger</h1>



<p align="center">

&#x20; <img src="https://img.shields.io/badge/Rust-000000?style=flat-square\&logo=rust\&logoColor=white" alt="Rust">

&#x20; <img src="https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square\&logo=javascript\&logoColor=black" alt="JavaScript">

&#x20; <img src="https://img.shields.io/badge/ML--KEM--768-FIPS%20203-0b7a6f?style=flat-square" alt="ML-KEM-768">

&#x20; <img src="https://img.shields.io/badge/AES--256--GCM-AEAD-1f6feb?style=flat-square" alt="AES-256-GCM">

&#x20; <img src="https://img.shields.io/badge/HKDF-SHA256-6e40c9?style=flat-square" alt="HKDF">

&#x20; <img src="https://img.shields.io/badge/WebSocket-Tokio-e8590c?style=flat-square" alt="WebSocket">

&#x20; <img src="https://img.shields.io/badge/Wireshark-Verified-1679a7?style=flat-square\&logo=wireshark\&logoColor=white" alt="Wireshark">

&#x20; <img src="https://img.shields.io/badge/Milestones-4%20of%204%20complete-4c1?style=flat-square" alt="Status">

</p>



<p align="center">

&#x20; End-to-end encrypted messenger using a post-quantum key exchange (ML-KEM-768),

&#x20; a ratcheted AES-256-GCM message layer, a zero-knowledge WebSocket relay, and a

&#x20; browser client with live encryption inspection. Source code, tests, and the

&#x20; security documentation for all 4 milestones.

</p>



\---



\## 📦 Repository Structure



```text

pq-messenger/

├── pq-kem/     # Milestones 1 \& 2: ML-KEM-768, key ratchet, AES-256-GCM (Rust)

├── pq-relay/   # Milestone 3: zero-knowledge WebSocket relay (Rust)

└── pq-web/     # Milestone 4: browser chat UI, e2e tests, security docs (JS)

```



\## 🗺️ Milestones



| # | Milestone | Folder | What was built |

|---|-----------|--------|----------------|

| 1 | Post-Quantum Key Encapsulation | `pq-kem` | ML-KEM-768 keygen, encapsulation/decapsulation to a 256-bit shared secret, NIST ACVP known-answer tests |

| 2 | Double Ratchet \& Symmetric Encryption | `pq-kem` | Root/chain key ratcheting (HKDF + HMAC), AES-256-GCM with a unique IV per message, MAC tamper detection |

| 3 | Asynchronous WebSocket Relay | `pq-relay` | Handshake with public-key discovery, ephemeral offline queues, rate limiting, replay protection |

| 4 | Terminal \& Web Interface | `pq-web` | Chat UI with live encryption metadata, network-capture proof of no plaintext leakage, architecture and threat model |



\## 🏗️ Architecture



```text

Alice (browser)                    Relay (opaque)                  Bob (browser)

&#x20;  │  register(ek\_A)  ───────────────►  │  ◄───────────────  register(ek\_B)  │

&#x20;  │  lookup(Bob)     ───────────────►  │                                    │

&#x20;  │  Encaps(ek\_B) → (ct, ss)           │                                    │

&#x20;  │  send(0x01‖ct)   ───────────────►  │  ───────────────►  Decaps(ct) → ss │

&#x20;  │  HKDF(ss) → root + chain keys      │      HKDF(ss) → root + chain keys  │

&#x20;  │  send(AES-256-GCM(msg))  ───────►  │  ───────────────►  verify tag, decrypt

```



\- \*\*Key exchange:\*\* ML-KEM-768 (FIPS 203), public key 1184 B, ciphertext 1088 B, shared secret 32 B

\- \*\*Key schedule:\*\* `HKDF-SHA256` → root key + two chain keys; `HMAC-SHA256` chain ratchet gives one key per message

\- \*\*Message layer:\*\* AES-256-GCM, random 96-bit IV, message counter authenticated as AAD

\- \*\*Relay:\*\* forwards opaque hex payloads and never parses or decrypts them



Full details: \[`pq-web/docs/ARCHITECTURE.md`](pq-web/docs/ARCHITECTURE.md) (cryptographic architecture and threat model).



\## 🚀 Quick Start



Prerequisites: \[Rust](https://rustup.rs) (stable), Node.js 18+ (only for the tests), and on Windows the \*Desktop development with C++\* build tools.



```bash

git clone https://github.com/harisaravananm/pq-messenger.git

cd pq-messenger

```



\### Milestones 1 \& 2: crypto core

```bash

cd pq-kem

cargo test      # NIST KAT + ratchet + tamper tests

cargo run       # prints a 256-bit shared secret

```



\### Milestone 3: relay server

```bash

cd pq-relay

cargo test      # handshake, queue, replay, rate-limit tests

cargo run       # ws://127.0.0.1:9001

```



\### Milestone 4: web client

Keep the relay running, then open `pq-web/dist/index.html` in \*\*two browser tabs\*\*:



1\. Enter a different username in each tab and click \*\*Connect\*\*

2\. In one tab, type the other username under \*Chats\* and click \*\*Start\*\*

3\. Send messages, and click any bubble to inspect its encryption metadata

4\. Use \*\*Send tampered\*\* to watch the MAC check reject a corrupted message



\## 🧪 Testing \& Verification



| Check | Command | Covers |

|-------|---------|--------|

| Rust unit/integration tests | `cargo test` in `pq-kem` and `pq-relay` | KAT vectors, ratchet, tamper, replay, queue, rate limit |

| End-to-end + wire capture | `cd pq-web \&\& npm install \&\& node test-e2e.mjs` | Full chat flow, sniffing proxy proves no plaintext on the wire, includes a negative control |

| Rust ↔ JS interoperability | `node test-interop.mjs "<n> <nonce> <ct>"` | A message encrypted in Rust decrypts in the browser code |



\### Wireshark proof (zero plaintext leakage)

Capture on the loopback adapter with filter `tcp port 9001`, send the phrase `TOP-SECRET-PLAINTEXT-4242`, then:



| Display filter | Expected |

|----------------|----------|

| `frame contains "TOP-SECRET-PLAINTEXT-4242"` | 0 packets |

| `websocket.payload.text contains "TOP-SECRET"` | 0 packets |

| `websocket.payload.text contains "payload"` | packets with hex ciphertext only |



Steps: \[`pq-web/docs/WIRESHARK.md`](pq-web/docs/WIRESHARK.md)



\## ⚠️ Known Limitations



This is an educational project and has not been independently audited.



\- No sender authentication: registration is unauthenticated (fix: ML-DSA signatures)

\- Static-key handshake: no forward secrecy if a user's private key later leaks (fix: signed ephemeral prekeys)

\- Demo transport is plain `ws://`: usernames, sizes, and timing are visible (use `wss://` in production)

\- The demo UI stores the private key in `localStorage`



Complete threat model: \[`ARCHITECTURE.md`](pq-web/docs/ARCHITECTURE.md#7-threat-model)



\## 📚 References



\- \[NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)

\- \[NIST ACVP test vectors](https://github.com/usnistgov/ACVP-Server)

\- \[RFC 5869: HKDF](https://www.rfc-editor.org/rfc/rfc5869)

\- \[Signal Double Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)



\## 📄 License



MIT

