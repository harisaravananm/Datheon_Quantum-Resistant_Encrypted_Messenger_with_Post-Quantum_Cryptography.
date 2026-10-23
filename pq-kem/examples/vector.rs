// Prints a message encrypted by the Rust ratchet so the JS client can prove wire-compatibility.
use pq_kem::Session;
fn main() {
    let mut a = Session::new(&[42u8; 32], true);
    let m = a.encrypt(b"hello from rust");
    println!("{} {} {}", m.n, hex::encode(m.nonce), hex::encode(&m.ct));
}
