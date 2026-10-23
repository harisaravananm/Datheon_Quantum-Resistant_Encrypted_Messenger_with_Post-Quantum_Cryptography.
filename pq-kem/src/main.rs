use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use pq_kem::Session;

fn main() {
    let mut rng = rand::thread_rng();
    // Milestone 1: KEM handshake
    let (dk, ek) = MlKem768::generate(&mut rng);
    let (ct, k_send) = ek.encapsulate(&mut rng).unwrap();
    let k_recv = dk.decapsulate(&ct).unwrap();
    assert_eq!(k_send, k_recv);
    println!("shared secret: {}", hex::encode(k_send));

    // Milestone 2: ratcheted AES-256-GCM messaging
    let mut alice = Session::new(&k_send, true);
    let mut bob = Session::new(&k_recv, false);
    for text in ["hello bob", "same text", "same text"] {
        let m = alice.encrypt(text.as_bytes());
        println!("msg {} nonce {} ct {}", m.n, hex::encode(m.nonce), hex::encode(&m.ct));
        println!("  bob decrypts: {}", String::from_utf8(bob.decrypt(&m).unwrap()).unwrap());
    }
    let reply = bob.encrypt(b"hi alice");
    println!("alice decrypts: {}", String::from_utf8(alice.decrypt(&reply).unwrap()).unwrap());
}
