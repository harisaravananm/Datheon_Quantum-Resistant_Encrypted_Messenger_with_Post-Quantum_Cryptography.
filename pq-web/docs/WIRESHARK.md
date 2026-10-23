# Wireshark proof of zero plaintext leakage (Windows)

1. Start the relay (`cargo run` in `pq-relay`) and open `dist/index.html` in two browser tabs (alice, bob).
2. Open Wireshark (install includes Npcap). Choose **Adapter for loopback traffic capture**. Capture filter: `tcp port 9001`. Start.
3. In the chat, send a unique phrase, e.g. `TOP-SECRET-PLAINTEXT-4242`, both directions. Stop the capture and save it as `capture.pcapng`.
4. Display filters (each should show **0 packets**):
   - `frame contains "TOP-SECRET-PLAINTEXT-4242"`
   - `websocket.payload.text contains "TOP-SECRET"`
   - `frame contains 544f502d534543524554` (the phrase in hex)
5. Control (should show packets): `websocket.payload.text contains "payload"`. Right-click one -> Follow -> TCP Stream. You will see JSON such as `{"type":"send","to":"bob","id":"...","payload":"02000000..."}`: usernames, ids and sizes are visible (metadata), the message content is not.
6. Screenshot steps 4 and 5 as evidence.

Note: browser-to-relay WebSocket frames are masked on the wire, so step 4's second filter (which uses Wireshark's decoded text) is the stronger check. `node test-e2e.mjs` runs the same check automatically through a sniffing proxy, with a negative control proving the check can detect plaintext.
