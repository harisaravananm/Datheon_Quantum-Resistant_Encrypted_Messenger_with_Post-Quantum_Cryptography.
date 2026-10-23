//! Milestone 3: zero-knowledge WebSocket relay.
//! Payloads are opaque strings: the relay never parses, decrypts or logs them.
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_tungstenite::tungstenite::Message as Ws;

pub const MAX_PAYLOAD: usize = 64 * 1024;
pub const MAX_KEY: usize = 8 * 1024;
pub const MAX_QUEUE: usize = 100; // offline messages per recipient
pub const QUEUE_TTL: Duration = Duration::from_secs(300);
pub const MAX_SEEN: usize = 10_000; // replay-cache size
pub const BURST: f64 = 10.0; // rate limit: burst size
pub const RATE: f64 = 5.0; //   ...and sustained msgs/sec per connection
pub const MAX_STRIKES: u8 = 5; // rate-limit violations before disconnect

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum In {
    Register { user: String, ek: String },
    Lookup { user: String },
    Send { to: String, id: String, payload: String },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Out<'a> {
    Registered { user: &'a str, queued: usize },
    Key { user: &'a str, ek: &'a str },
    Msg { from: &'a str, id: &'a str, payload: &'a str },
    Ack { id: &'a str },
    Error { reason: &'a str },
}

type Tx = UnboundedSender<String>;
fn out(tx: &Tx, o: Out) { let _ = tx.send(serde_json::to_string(&o).unwrap()); }
fn err(tx: &Tx, reason: &str) { out(tx, Out::Error { reason }); }

/// Token bucket (time passed in so it is testable).
pub struct Bucket { cap: f64, rate: f64, tokens: f64, last: Instant }
impl Bucket {
    pub fn new(cap: f64, rate: f64, now: Instant) -> Self { Bucket { cap, rate, tokens: cap, last: now } }
    pub fn allow(&mut self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.cap);
        if self.tokens >= 1.0 { self.tokens -= 1.0; true } else { false }
    }
}

struct Queued { at: Instant, from: String, id: String, payload: String }
type SeenKey = (String, String, String); // (from, to, id)

#[derive(Default)]
pub struct State {
    keys: HashMap<String, String>,                 // user -> public key (hex)
    online: HashMap<String, Tx>,                   // user -> live connection
    queues: HashMap<String, VecDeque<Queued>>,     // ephemeral, memory only
    seen: HashSet<SeenKey>,
    seen_order: VecDeque<SeenKey>,
}
pub type Shared = Arc<Mutex<State>>;

fn valid_user(u: &str) -> bool {
    !u.is_empty() && u.len() <= 32 && u.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}
fn is_hex(s: &str) -> bool { !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit()) }

fn process(st: &mut State, me: &mut Option<String>, tx: &Tx, msg: In, now: Instant) {
    match msg {
        In::Register { user, ek } => {
            if me.is_some() { return err(tx, "already_registered"); }
            if !valid_user(&user) { return err(tx, "bad_username"); }
            if !is_hex(&ek) || ek.len() > MAX_KEY { return err(tx, "bad_key"); }
            match st.keys.get(&user) {
                Some(k) if *k != ek => return err(tx, "name_taken"),
                _ => {}
            }
            if st.online.get(&user).map_or(false, |t| !t.is_closed()) { return err(tx, "already_connected"); }
            st.keys.insert(user.clone(), ek);
            st.online.insert(user.clone(), tx.clone());
            let q = st.queues.remove(&user).unwrap_or_default();
            let live: Vec<Queued> = q.into_iter().filter(|m| now.saturating_duration_since(m.at) < QUEUE_TTL).collect();
            out(tx, Out::Registered { user: &user, queued: live.len() });
            for m in &live { out(tx, Out::Msg { from: &m.from, id: &m.id, payload: &m.payload }); } // queue is now gone
            *me = Some(user);
        }
        In::Lookup { user } => match st.keys.get(&user) {
            Some(ek) => out(tx, Out::Key { user: &user, ek }),
            None => err(tx, "unknown_user"),
        },
        In::Send { to, id, payload } => {
            let Some(from) = me.clone() else { return err(tx, "not_registered") };
            if id.is_empty() || id.len() > 64 { return err(tx, "bad_id"); }
            if payload.len() > MAX_PAYLOAD { return err(tx, "payload_too_large"); }
            if !st.keys.contains_key(&to) { return err(tx, "unknown_user"); }
            let key = (from.clone(), to.clone(), id.clone());
            if st.seen.contains(&key) { return err(tx, "replay"); }
            // deliver live, else queue
            let delivered = match st.online.get(&to) {
                Some(t) if !t.is_closed() => { out(t, Out::Msg { from: &from, id: &id, payload: &payload }); true }
                _ => false,
            };
            if !delivered {
                st.online.remove(&to);
                let q = st.queues.entry(to.clone()).or_default();
                while q.front().map_or(false, |m| now.saturating_duration_since(m.at) >= QUEUE_TTL) { q.pop_front(); }
                if q.len() >= MAX_QUEUE { return err(tx, "queue_full"); }
                q.push_back(Queued { at: now, from, id: id.clone(), payload });
            }
            st.seen.insert(key.clone());
            st.seen_order.push_back(key);
            if st.seen_order.len() > MAX_SEEN { if let Some(old) = st.seen_order.pop_front() { st.seen.remove(&old); } }
            out(tx, Out::Ack { id: &id });
        }
    }
}

async fn handle(stream: TcpStream, st: Shared) {
    let Ok(ws) = tokio_tungstenite::accept_async(stream).await else { return };
    let (mut sink, mut rx_ws) = ws.split();
    let (tx, mut rx) = unbounded_channel::<String>();
    let writer = tokio::spawn(async move {
        while let Some(s) = rx.recv().await {
            if sink.send(Ws::Text(s.into())).await.is_err() { break; }
        }
    });
    let mut me: Option<String> = None;
    let mut bucket = Bucket::new(BURST, RATE, Instant::now());
    let mut strikes = 0u8;
    while let Some(Ok(frame)) = rx_ws.next().await {
        let text = match frame { Ws::Text(t) => t, Ws::Close(_) => break, _ => continue };
        let now = Instant::now();
        if !bucket.allow(now) {
            strikes += 1;
            err(&tx, "rate_limited");
            if strikes >= MAX_STRIKES { break; }
            continue;
        }
        if text.as_str().len() > MAX_PAYLOAD + 2048 { err(&tx, "frame_too_large"); continue; }
        match serde_json::from_str::<In>(text.as_str()) {
            Ok(m) => process(&mut st.lock().unwrap(), &mut me, &tx, m, now),
            Err(_) => err(&tx, "bad_request"),
        }
    }
    if let Some(u) = me {
        let mut g = st.lock().unwrap();
        if g.online.get(&u).map_or(false, |t| t.same_channel(&tx)) { g.online.remove(&u); }
    }
    drop(tx); // let the writer flush pending replies, then close
    let _ = writer.await;
}

pub async fn serve(listener: TcpListener) {
    let st: Shared = Arc::default();
    loop {
        if let Ok((s, _)) = listener.accept().await { tokio::spawn(handle(s, st.clone())); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bucket_limits_then_refills() {
        let t0 = Instant::now();
        let mut b = Bucket::new(3.0, 1.0, t0);
        assert!(b.allow(t0) && b.allow(t0) && b.allow(t0));
        assert!(!b.allow(t0));
        assert!(b.allow(t0 + Duration::from_secs(1)));
    }
    #[test]
    fn queue_expires_after_ttl() {
        let (tx_a, _ra) = unbounded_channel();
        let (tx_b, mut rb) = unbounded_channel();
        let (mut st, mut a, mut b) = (State::default(), None, None);
        let t0 = Instant::now();
        process(&mut st, &mut b, &tx_b, In::Register { user: "bob".into(), ek: "aa".into() }, t0);
        st.online.remove("bob"); b = None; let _ = b;
        process(&mut st, &mut a, &tx_a, In::Register { user: "alice".into(), ek: "bb".into() }, t0);
        process(&mut st, &mut a, &tx_a, In::Send { to: "bob".into(), id: "1".into(), payload: "cc".into() }, t0);
        let (tx_b2, mut rb2) = unbounded_channel();
        let mut b2 = None;
        process(&mut st, &mut b2, &tx_b2, In::Register { user: "bob".into(), ek: "aa".into() }, t0 + QUEUE_TTL + Duration::from_secs(1));
        assert!(rb2.try_recv().unwrap().contains("\"queued\":0"));
        assert!(rb2.try_recv().is_err());
        let _ = rb.try_recv();
    }
}
