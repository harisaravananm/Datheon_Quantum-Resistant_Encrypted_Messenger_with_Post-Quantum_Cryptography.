use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};

#[test]
fn roundtrip_256bit_secret() {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);
    let (ct, k1) = ek.encapsulate(&mut rng).unwrap();
    assert_eq!(k1, dk.decapsulate(&ct).unwrap());
    assert_eq!(k1.len(), 32);
}

#[test]
fn tampered_ciphertext_gives_different_secret() {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);
    let (mut ct, k1) = ek.encapsulate(&mut rng).unwrap();
    ct[0] ^= 1;
    assert_ne!(k1, dk.decapsulate(&ct).unwrap());
}
