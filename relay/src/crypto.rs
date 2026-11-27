//! Stage 4 Standard Transport Cryptography:
//!   - ECDHE over NIST P-256 (`p256`) for per-session Perfect Forward Secrecy
//!   - PSK mutual authentication via HMAC-SHA256 (`hmac` + `sha2` + `subtle`)
//!   - Directional key derivation via RFC 5869 HKDF-SHA256 (`hkdf`)
//!   - Packet AEAD encryption via RFC 8439 ChaCha20-Poly1305 (`chacha20poly1305`)
//!   - 64-packet sliding Anti-Replay Window (RFC 6479 style, updated only post-AEAD)

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const AEAD_TAG_BYTES: usize = 16;
pub const P256_UNCOMPRESSED_PUB_BYTES: usize = 65;
pub const HANDSHAKE_NONCE_BYTES: usize = 16;
pub const HANDSHAKE_TAG_BYTES: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// Derive a 32-byte PSK key from an operator passphrase/secret string.
pub fn derive_psk_key(psk: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"jiter-psk-v1:");
    hasher.update(psk.trim().as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn random_nonce_16() -> [u8; HANDSHAKE_NONCE_BYTES] {
    let mut out = [0u8; HANDSHAKE_NONCE_BYTES];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn constant_time_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    bool::from(a.ct_eq(b))
}

pub fn compute_hello_req_tag(
    psk_key: &[u8; 32],
    session_id: u32,
    body_before_tag: &[u8],
) -> [u8; HANDSHAKE_TAG_BYTES] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(psk_key).expect("valid hmac key");
    mac.update(b"jiter-hello-req-v1");
    mac.update(&session_id.to_be_bytes());
    mac.update(body_before_tag);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; HANDSHAKE_TAG_BYTES];
    tag.copy_from_slice(&full[..HANDSHAKE_TAG_BYTES]);
    tag
}

pub fn compute_hello_ack_tag(
    psk_key: &[u8; 32],
    session_id: u32,
    client_nonce: &[u8; HANDSHAKE_NONCE_BYTES],
    body_before_tag: &[u8],
) -> [u8; HANDSHAKE_TAG_BYTES] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(psk_key).expect("valid hmac key");
    mac.update(b"jiter-hello-ack-v1");
    mac.update(&session_id.to_be_bytes());
    mac.update(client_nonce);
    mac.update(body_before_tag);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; HANDSHAKE_TAG_BYTES];
    tag.copy_from_slice(&full[..HANDSHAKE_TAG_BYTES]);
    tag
}

pub struct EphemeralP256KeyPair {
    secret: EphemeralSecret,
    public_uncompressed: [u8; P256_UNCOMPRESSED_PUB_BYTES],
}

impl EphemeralP256KeyPair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let pub_key = secret.public_key();
        let encoded = pub_key.to_encoded_point(false);
        let bytes = encoded.as_bytes();
        let mut public_uncompressed = [0u8; P256_UNCOMPRESSED_PUB_BYTES];
        public_uncompressed.copy_from_slice(bytes);
        Self {
            secret,
            public_uncompressed,
        }
    }

    pub fn public_bytes(&self) -> [u8; P256_UNCOMPRESSED_PUB_BYTES] {
        self.public_uncompressed
    }

    pub fn diffie_hellman(self, peer_pub_bytes: &[u8; P256_UNCOMPRESSED_PUB_BYTES]) -> Option<[u8; 32]> {
        let peer_pub = PublicKey::from_sec1_bytes(peer_pub_bytes).ok()?;
        let shared = self.secret.diffie_hellman(&peer_pub);
        let mut out = [0u8; 32];
        out.copy_from_slice(shared.raw_secret_bytes().as_slice());
        Some(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeyMaterial {
    pub c2s_key: [u8; 32],
    pub s2c_key: [u8; 32],
    pub c2s_iv: [u8; 4],
    pub s2c_iv: [u8; 4],
}

/// RFC 5869 HKDF-SHA256 directional key derivation combining ECDHE shared secret + PSK.
pub fn derive_session_keys(
    ecdh_shared: &[u8; 32],
    psk_key: &[u8; 32],
    client_nonce: &[u8; HANDSHAKE_NONCE_BYTES],
    server_nonce: &[u8; HANDSHAKE_NONCE_BYTES],
    session_id: u32,
) -> SessionKeyMaterial {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ecdh_shared);
    ikm[32..].copy_from_slice(psk_key);

    let mut salt = [0u8; 36];
    salt[..16].copy_from_slice(client_nonce);
    salt[16..32].copy_from_slice(server_nonce);
    salt[32..36].copy_from_slice(&session_id.to_be_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);

    let mut c2s_key = [0u8; 32];
    let mut s2c_key = [0u8; 32];
    let mut c2s_iv = [0u8; 4];
    let mut s2c_iv = [0u8; 4];

    hk.expand(b"jiter-v1-c2s-key", &mut c2s_key)
        .expect("hkdf c2s_key");
    hk.expand(b"jiter-v1-s2c-key", &mut s2c_key)
        .expect("hkdf s2c_key");
    hk.expand(b"jiter-v1-c2s-iv", &mut c2s_iv)
        .expect("hkdf c2s_iv");
    hk.expand(b"jiter-v1-s2c-iv", &mut s2c_iv)
        .expect("hkdf s2c_iv");

    SessionKeyMaterial {
        c2s_key,
        s2c_key,
        c2s_iv,
        s2c_iv,
    }
}

/// 64-packet sliding Anti-Replay Window (RFC 6479).
/// Call `would_accept(seq)` before AEAD decrypt, and `mark_accepted(seq)` ONLY after AEAD passes.
#[derive(Debug, Default, Clone)]
pub struct ReplayWindow {
    initialized: bool,
    highest: u32,
    bitmap: u64,
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn would_accept(&self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        if !self.initialized {
            return true;
        }
        if seq > self.highest {
            return true;
        }
        let diff = self.highest - seq;
        if diff >= 64 {
            return false;
        }
        (self.bitmap & (1u64 << diff)) == 0
    }

    pub fn mark_accepted(&mut self, seq: u32) {
        if seq == 0 {
            return;
        }
        if !self.initialized {
            self.initialized = true;
            self.highest = seq;
            self.bitmap = 1u64;
            return;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            if shift >= 64 {
                self.bitmap = 1u64;
            } else {
                self.bitmap = (self.bitmap << shift) | 1u64;
            }
            self.highest = seq;
        } else {
            let diff = self.highest - seq;
            if diff < 64 {
                self.bitmap |= 1u64 << diff;
            }
        }
    }
}

/// Directional ChaCha20-Poly1305 AEAD session cipher with Anti-Replay Window.
pub struct SessionCipher {
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
    tx_iv: [u8; 4],
    rx_iv: [u8; 4],
    replay_window: ReplayWindow,
}

impl SessionCipher {
    /// Server-side constructor: decrypts C2S, encrypts S2C.
    pub fn for_server(keys: &SessionKeyMaterial) -> Self {
        Self {
            tx_cipher: <ChaCha20Poly1305 as KeyInit>::new_from_slice(&keys.s2c_key)
                .expect("32-byte key"),
            rx_cipher: <ChaCha20Poly1305 as KeyInit>::new_from_slice(&keys.c2s_key)
                .expect("32-byte key"),
            tx_iv: keys.s2c_iv,
            rx_iv: keys.c2s_iv,
            replay_window: ReplayWindow::new(),
        }
    }

    /// Client-side constructor (also used in integration tests): encrypts C2S, decrypts S2C.
    pub fn for_client(keys: &SessionKeyMaterial) -> Self {
        Self {
            tx_cipher: <ChaCha20Poly1305 as KeyInit>::new_from_slice(&keys.c2s_key)
                .expect("32-byte key"),
            rx_cipher: <ChaCha20Poly1305 as KeyInit>::new_from_slice(&keys.s2c_key)
                .expect("32-byte key"),
            tx_iv: keys.c2s_iv,
            rx_iv: keys.s2c_iv,
            replay_window: ReplayWindow::new(),
        }
    }

    fn build_nonce(iv: &[u8; 4], session_id: u32, sequence: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(iv);
        nonce[4..8].copy_from_slice(&session_id.to_be_bytes());
        nonce[8..12].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }

    pub fn encrypt(
        &self,
        session_id: u32,
        sequence: u32,
        aad_header: &[u8],
        plaintext: &[u8],
    ) -> Option<Vec<u8>> {
        let nonce_bytes = Self::build_nonce(&self.tx_iv, session_id, sequence);
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.tx_cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: aad_header,
                },
            )
            .ok()
    }

    pub fn decrypt_and_check_replay(
        &mut self,
        session_id: u32,
        sequence: u32,
        aad_header: &[u8],
        ciphertext: &[u8],
    ) -> Option<Vec<u8>> {
        if ciphertext.len() < AEAD_TAG_BYTES {
            return None;
        }
        if !self.replay_window.would_accept(sequence) {
            return None;
        }
        let nonce_bytes = Self::build_nonce(&self.rx_iv, session_id, sequence);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = self
            .rx_cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: aad_header,
                },
            )
            .ok()?;
        // Update replay window strictly AFTER Poly1305 authentication succeeds
        self.replay_window.mark_accepted(sequence);
        Some(plaintext)
    }
}
