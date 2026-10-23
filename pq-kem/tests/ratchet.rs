use pq_kem::{Error, Session};

fn pair() -> (Session, Session) {
    let k = [42u8; 32];
    (Session::new(&k, true), Session::new(&k, false))
}

#[test]
fn both_directions_roundtrip() {
    let (mut a, mut b) = pair();
    for i in 0..5u8 {
        let m = a.encrypt(&[i; 20]);
        assert_eq!(b.decrypt(&m).unwrap(), vec![i; 20]);
        let r = b.encrypt(&[i + 100; 7]);
        assert_eq!(a.decrypt(&r).unwrap(), vec![i + 100; 7]);
    }
}

#[test]
fn unique_iv_and_ciphertext_for_same_plaintext() {
    let (mut a, _) = pair();
    let m1 = a.encrypt(b"same");
    let m2 = a.encrypt(b"same");
    assert_ne!(m1.nonce, m2.nonce);
    assert_ne!(m1.ct, m2.ct);
}

#[test]
fn tampered_ciphertext_rejected() {
    let (mut a, mut b) = pair();
    let mut m = a.encrypt(b"secret");
    m.ct[0] ^= 1;
    assert_eq!(b.decrypt(&m), Err(Error::AuthFailed));
}

#[test]
fn tampered_tag_rejected() {
    let (mut a, mut b) = pair();
    let mut m = a.encrypt(b"secret");
    let last = m.ct.len() - 1;
    m.ct[last] ^= 1;
    assert_eq!(b.decrypt(&m), Err(Error::AuthFailed));
}

#[test]
fn tampered_nonce_rejected() {
    let (mut a, mut b) = pair();
    let mut m = a.encrypt(b"secret");
    m.nonce[0] ^= 1;
    assert_eq!(b.decrypt(&m), Err(Error::AuthFailed));
}

#[test]
fn replay_and_reorder_rejected() {
    let (mut a, mut b) = pair();
    let m0 = a.encrypt(b"zero");
    let m1 = a.encrypt(b"one");
    assert_eq!(b.decrypt(&m1), Err(Error::OutOfOrder)); // skipped m0
    assert!(b.decrypt(&m0).is_ok());
    assert_eq!(b.decrypt(&m0), Err(Error::OutOfOrder)); // replay
    assert!(b.decrypt(&m1).is_ok());
}

#[test]
fn failed_auth_does_not_advance_chain() {
    let (mut a, mut b) = pair();
    let good = a.encrypt(b"x");
    let mut bad = good.clone();
    bad.ct[0] ^= 1;
    assert!(b.decrypt(&bad).is_err());
    assert!(b.decrypt(&good).is_ok());
}

#[test]
fn wrong_key_cannot_decrypt() {
    let (mut a, _) = pair();
    let mut eve = Session::new(&[7u8; 32], false);
    assert_eq!(eve.decrypt(&a.encrypt(b"secret")), Err(Error::AuthFailed));
}

#[test]
fn root_ratchet_keeps_sessions_in_sync_and_cuts_off_old_chain() {
    let (mut a, mut b) = pair();
    let mut stale = Session::new(&[42u8; 32], false); // attacker who held the old state
    assert!(b.decrypt(&a.encrypt(b"before")).is_ok());
    let fresh = [9u8; 32];
    a.ratchet_root(&fresh);
    b.ratchet_root(&fresh);
    let m = a.encrypt(b"after");
    assert_eq!(b.decrypt(&m).unwrap(), b"after");
    assert!(stale.decrypt(&m).is_err()); // old state can't read post-ratchet traffic
}
