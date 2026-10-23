//! Milestone 2: symmetric double-ratchet core with AES-256-GCM.
//! Root key (from ML-KEM shared secret) -> chain keys -> per-message keys.
use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha = Hmac<Sha256>;

#[derive(Debug, PartialEq)]
pub enum Error { OutOfOrder, AuthFailed }

#[derive(Clone, Debug)]
pub struct Message { pub n: u32, pub nonce: [u8; 12], pub ct: Vec<u8> } // ct = ciphertext || 16-byte GCM tag

fn hmac(key: &[u8; 32], tag: u8) -> [u8; 32] {
    let mut m = <HmacSha as Mac>::new_from_slice(key).unwrap();
    m.update(&[tag]);
    m.finalize().into_bytes().into()
}

/// KDF_RK: (root key, input secret) -> (new root, chain A->B, chain B->A)
fn kdf_root(rk: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut out = [0u8; 96];
    Hkdf::<Sha256>::new(Some(rk), input).expand(b"pq-messenger/root", &mut out).unwrap();
    (out[..32].try_into().unwrap(), out[32..64].try_into().unwrap(), out[64..].try_into().unwrap())
}

pub struct Session { root: [u8; 32], send_ck: [u8; 32], recv_ck: [u8; 32], send_n: u32, recv_n: u32, initiator: bool }

impl Session {
    /// `shared` = 32-byte ML-KEM secret. Initiator = the side that encapsulated.
    pub fn new(shared: &[u8], initiator: bool) -> Self {
        let mut s = Session { root: [0; 32], send_ck: [0; 32], recv_ck: [0; 32], send_n: 0, recv_n: 0, initiator };
        s.step_root(&[0u8; 32], shared);
        s
    }
    fn step_root(&mut self, rk: &[u8; 32], input: &[u8]) {
        let (root, a2b, b2a) = kdf_root(rk, input);
        self.root = root;
        (self.send_ck, self.recv_ck) = if self.initiator { (a2b, b2a) } else { (b2a, a2b) };
        self.send_n = 0;
        self.recv_n = 0;
    }
    /// Root-key ratchet: both sides call with the same fresh KEM secret (post-compromise recovery).
    pub fn ratchet_root(&mut self, fresh_kem_secret: &[u8]) {
        let rk = self.root;
        self.step_root(&rk, fresh_kem_secret);
    }
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Message {
        let mk = hmac(&self.send_ck, 0x01);
        self.send_ck = hmac(&self.send_ck, 0x02); // chain ratchet: old key is gone
        let n = self.send_n;
        self.send_n += 1;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce); // unique IV per message
        let ct = Aes256Gcm::new(&mk.into())
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &n.to_be_bytes() })
            .unwrap();
        Message { n, nonce, ct }
    }
    pub fn decrypt(&mut self, m: &Message) -> Result<Vec<u8>, Error> {
        if m.n != self.recv_n { return Err(Error::OutOfOrder); } // also blocks replay
        let mk = hmac(&self.recv_ck, 0x01);
        let pt = Aes256Gcm::new(&mk.into())
            .decrypt(Nonce::from_slice(&m.nonce), Payload { msg: &m.ct, aad: &m.n.to_be_bytes() })
            .map_err(|_| Error::AuthFailed)?;
        self.recv_ck = hmac(&self.recv_ck, 0x02); // advance only after a valid MAC
        self.recv_n += 1;
        Ok(pt)
    }
}
