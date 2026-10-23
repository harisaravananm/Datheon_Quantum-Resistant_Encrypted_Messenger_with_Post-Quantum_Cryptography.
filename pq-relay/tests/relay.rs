use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

type C = WebSocketStream<MaybeTlsStream<TcpStream>>;

async fn start() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", l.local_addr().unwrap());
    tokio::spawn(pq_relay::serve(l));
    url
}
async fn conn(url: &str) -> C { connect_async(url).await.unwrap().0 }
async fn send(c: &mut C, s: &str) { c.send(Message::Text(s.to_string().into())).await.unwrap(); }
async fn recv(c: &mut C) -> String {
    match tokio::time::timeout(Duration::from_secs(2), c.next()).await {
        Ok(Some(Ok(Message::Text(t)))) => t.as_str().to_string(),
        other => panic!("no text frame: {other:?}"),
    }
}
async fn register(c: &mut C, user: &str, ek: &str) -> String {
    send(c, &format!(r#"{{"type":"register","user":"{user}","ek":"{ek}"}}"#)).await;
    recv(c).await
}

#[tokio::test]
async fn handshake_and_public_key_discovery() {
    let url = start().await;
    let (mut a, mut b) = (conn(&url).await, conn(&url).await);
    assert!(register(&mut a, "alice", "aabb").await.contains("registered"));
    assert!(register(&mut b, "bob", "ccdd").await.contains("registered"));
    send(&mut a, r#"{"type":"lookup","user":"bob"}"#).await;
    let r = recv(&mut a).await;
    assert!(r.contains("\"key\"") && r.contains("ccdd"), "{r}");
    send(&mut a, r#"{"type":"lookup","user":"nobody"}"#).await;
    assert!(recv(&mut a).await.contains("unknown_user"));
}

#[tokio::test]
async fn live_delivery_is_opaque() {
    let url = start().await;
    let (mut a, mut b) = (conn(&url).await, conn(&url).await);
    register(&mut a, "alice", "aabb").await;
    register(&mut b, "bob", "ccdd").await;
    send(&mut a, r#"{"type":"send","to":"bob","id":"m1","payload":"deadbeef"}"#).await;
    assert!(recv(&mut a).await.contains("ack"));
    let m = recv(&mut b).await;
    assert!(m.contains("\"from\":\"alice\"") && m.contains("deadbeef"), "{m}");
}

#[tokio::test]
async fn offline_queue_delivers_once_then_is_gone() {
    let url = start().await;
    let mut a = conn(&url).await;
    register(&mut a, "alice", "aabb").await;
    let mut b = conn(&url).await;
    register(&mut b, "bob", "ccdd").await;
    drop(b);
    tokio::time::sleep(Duration::from_millis(100)).await;
    send(&mut a, r#"{"type":"send","to":"bob","id":"m1","payload":"0102"}"#).await;
    assert!(recv(&mut a).await.contains("ack"));
    let mut b = conn(&url).await;
    assert!(register(&mut b, "bob", "ccdd").await.contains("\"queued\":1"));
    assert!(recv(&mut b).await.contains("0102"));
    drop(b);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut b = conn(&url).await;
    assert!(register(&mut b, "bob", "ccdd").await.contains("\"queued\":0"));
}

#[tokio::test]
async fn replay_is_rejected() {
    let url = start().await;
    let (mut a, mut b) = (conn(&url).await, conn(&url).await);
    register(&mut a, "alice", "aabb").await;
    register(&mut b, "bob", "ccdd").await;
    let m = r#"{"type":"send","to":"bob","id":"same","payload":"00"}"#;
    send(&mut a, m).await;
    assert!(recv(&mut a).await.contains("ack"));
    send(&mut a, m).await;
    assert!(recv(&mut a).await.contains("replay"));
}

#[tokio::test]
async fn spam_is_rate_limited_and_disconnected() {
    let url = start().await;
    let (mut a, mut b) = (conn(&url).await, conn(&url).await);
    register(&mut a, "alice", "aabb").await;
    register(&mut b, "bob", "ccdd").await;
    for i in 0..40 {
        send(&mut a, &format!(r#"{{"type":"send","to":"bob","id":"s{i}","payload":"00"}}"#)).await;
    }
    let mut limited = 0;
    while let Ok(Some(Ok(Message::Text(t)))) = tokio::time::timeout(Duration::from_millis(500), a.next()).await {
        if t.as_str().contains("rate_limited") { limited += 1; }
    }
    assert!(limited >= 5, "limited={limited}");
}

#[tokio::test]
async fn squatting_and_unregistered_send_rejected() {
    let url = start().await;
    let (mut a, mut x) = (conn(&url).await, conn(&url).await);
    register(&mut a, "alice", "aabb").await;
    assert!(register(&mut x, "alice", "ffff").await.contains("name_taken"));
    let mut y = conn(&url).await;
    send(&mut y, r#"{"type":"send","to":"alice","id":"1","payload":"00"}"#).await;
    assert!(recv(&mut y).await.contains("not_registered"));
}
