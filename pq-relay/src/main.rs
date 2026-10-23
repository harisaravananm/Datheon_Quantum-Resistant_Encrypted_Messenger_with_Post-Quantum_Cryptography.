#[tokio::main]
async fn main() {
    let addr = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:9001".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("pq-relay listening on ws://{addr}");
    pq_relay::serve(listener).await;
}
