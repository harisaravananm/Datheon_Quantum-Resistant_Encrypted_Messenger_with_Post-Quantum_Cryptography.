# PQ Messenger: Cryptographic Architecture & Threat Model

## 1. Components
| Part | Language | Role |
|---|---|---|
| `pq-kem` | Rust | ML-KEM-768 (FIPS 203) + symmetric ratchet + AES-256-GCM. Tested against NIST ACVP vectors. |
| `pq-relay` | Rust | WebSocket relay: public-key directory, offline queue, rate limit, replay cache. Never parses payloads. |
| `pq-web` | JS | Browser client (single HTML file). Same protocol as `pq-kem`; proven wire-compatible (`test-interop.mjs`). |

## 2. Handshake (post-quantum key establishment)
1. Bob generates an ML-KEM-768 keypair (ek 1184 B, dk 2400 B) and registers `ek` with the relay.
2. Alice looks up `ek_bob`, runs `Encaps(ek_bob)` -> (ct 1088 B, ss 32 B), sends `0x01 || ct`.
3. Bob runs `Decaps(ct, dk_bob)` -> the same `ss`.
4. Both display a **safety number** = SHA-256("pq-messenger/safety" || sorted(ek_a, ek_b)), grouped as digits, to compare out-of-band.

## 3. Key schedule
```
(RK1, CK_a2b, CK_b2a) = HKDF-SHA256(salt = 0^32, ikm = ss, info = "pq-messenger/root", L = 96)
MK_n   = HMAC-SHA256(CK_n, 0x01)      message key, used once
CK_n+1 = HMAC-SHA256(CK_n, 0x02)      chain ratchet; CK_n is then overwritten
RK'    = HKDF(salt = RK, ikm = fresh KEM secret)   root ratchet (ratchet_root)
```

## 4. Message protection
`0x02 || n (4 B BE) || nonce (12 B random) || AES-256-GCM(MK_n, nonce, aad = n, plaintext) || tag (16 B)`
- Unique IV per message (and a unique key per message).
- Tag covers ciphertext and counter. A message that fails verification is rejected **without advancing** the chain.
- Receiver accepts only `n == expected`, so replays and reordering are rejected.

## 5. Relay protocol (JSON over WebSocket)
`register {user, ek}`, `lookup {user}`, `send {to, id, payload}`. `payload` is an opaque hex string.
Relay limits: 5 msg/s sustained and burst 10 per connection (disconnect after 5 violations), 64 KB payload, 100 queued messages per user for 5 min (memory only, deleted on delivery), replay cache of `(from, to, id)` for the last 10,000 messages.

## 6. What each party can see
| Party | Sees | Cannot see |
|---|---|---|
| Passive network observer (ws://) | usernames, public keys, message ids, sizes, timing, ciphertext | plaintext, session keys |
| Relay | same as above, plus who talks to whom | plaintext, session keys |
| Peer | plaintext they are sent | other conversations |

## 7. Threat model
| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | Harvest-now-decrypt-later by a quantum adversary | ML-KEM-768 key exchange, AES-256 data encryption | Transport is plain `ws://`; use `wss://` to hide metadata (classical TLS unless hybrid PQ TLS is enabled). |
| T2 | Message tampering in transit | GCM tag + counter as AAD; failed message does not change state | None known. |
| T3 | Replay / reorder | Client counter check + relay `(from,to,id)` cache | Relay cache is bounded; the client counter is the durable defense. |
| T4 | Spam / flooding / queue exhaustion | Token bucket, disconnect on abuse, size and queue caps, TTL | No authentication, so one attacker can open many identities (Sybil). |
| T5 | Malicious relay swaps public keys (MITM) | Safety-number comparison out-of-band | Only protects users who actually compare numbers. |
| T6 | Impersonation / queue theft | Relay refuses a different key for a registered name | Public keys are public: anyone who knows Bob's `ek` can register as Bob when he is offline. Sender and registrant are not authenticated. Fix: ML-DSA signatures or a KEM challenge at registration. |
| T7 | Later compromise of long-term `dk` | Per-message keys are deleted | **No forward secrecy against `dk` leakage**: the handshake encapsulates to a static key, so a recorded `ct` plus a leaked `dk` reveals `ss`. Fix: signed ephemeral prekeys (PQXDH-style) and rotating `ek`. |
| T8 | Compromise of a chain key | Chain ratchet limits damage to later messages in that chain | Root ratchet is available (`ratchet_root`) but not triggered automatically; post-compromise recovery is limited. |
| T9 | Endpoint compromise | Out of scope | Demo UI stores `dk` in `localStorage` in plaintext. Do not use for real secrets. |
| T10 | Implementation flaws | KAT + tamper + replay tests, Rust/JS cross-check | Libraries (`ml-kem`, `@noble/post-quantum`) are not independently audited by us; timing side channels not assessed. |

## 8. Out of scope
Traffic analysis, group chats, multi-device, persistent history, deniability.

## 9. Evidence
`cargo test` (pq-kem: NIST KAT, ratchet, tamper) · `cargo test` (pq-relay: handshake, queue, replay, rate limit) · `node test-e2e.mjs` (full flow + wire capture with negative control) · `node test-interop.mjs` (Rust-encrypted message decrypts in JS) · Wireshark capture (`WIRESHARK.md`).
