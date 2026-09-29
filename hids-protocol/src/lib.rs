//! Shared encrypted control-plane protocol for the HIDS agent and server.
//!
//! Payloads are serialized as JSON, compressed with zstd, then authenticated
//! and encrypted with ChaCha20-Poly1305.

use std::io::{Cursor, Read};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, OsRng},
};
use rand::RngCore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const COMPRESSION_LEVEL: i32 = 3;
const MAX_DECOMPRESSED_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureEnvelope {
    pub version: u8,
    pub algorithm: String,
    pub compression: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineCommand {
    pub request_id: String,
    pub host_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub checks: Vec<BaselineCheckSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineCheckSpec {
    pub id: String,
    pub kind: BaselineCheckKind,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineCheckKind {
    SystemInfo,
    ListeningPorts,
    ProcessSummary,
    FileHashes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineResult {
    pub request_id: String,
    pub host_id: String,
    pub completed_at_ms: u64,
    pub results: Vec<BaselineCheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineCheckResult {
    pub id: String,
    pub kind: BaselineCheckKind,
    pub status: BaselineStatus,
    pub summary: String,
    #[serde(default)]
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStatus {
    Ok,
    Failed,
    Rejected,
}

pub fn parse_key(input: &str) -> anyhow::Result<[u8; 32]> {
    let value = input.trim();
    if value.is_empty() {
        anyhow::bail!("control-plane key is empty");
    }

    if value.len() == KEY_LEN * 2 {
        let mut out = [0u8; KEY_LEN];
        for (i, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)
                .map_err(|_| anyhow::anyhow!("control-plane key is not valid hex"))?;
        }
        return Ok(out);
    }

    let decoded = B64
        .decode(value)
        .map_err(|_| anyhow::anyhow!("control-plane key must be 64 hex chars or base64"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("control-plane key must decode to 32 bytes"))
}

pub fn seal_json<T: Serialize>(
    value: &T,
    key_bytes: &[u8; KEY_LEN],
) -> anyhow::Result<SecureEnvelope> {
    let raw = serde_json::to_vec(value)?;
    let compressed = zstd::stream::encode_all(Cursor::new(raw), COMPRESSION_LEVEL)?;

    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, compressed.as_ref())
        .map_err(|_| anyhow::anyhow!("control-plane encryption failed"))?;

    Ok(SecureEnvelope {
        version: 1,
        algorithm: "chacha20poly1305".to_string(),
        compression: "zstd".to_string(),
        nonce: B64.encode(nonce_bytes),
        ciphertext: B64.encode(ciphertext),
    })
}

pub fn open_json<T: DeserializeOwned>(
    envelope: &SecureEnvelope,
    key_bytes: &[u8; KEY_LEN],
) -> anyhow::Result<T> {
    if envelope.version != 1
        || envelope.algorithm != "chacha20poly1305"
        || envelope.compression != "zstd"
    {
        anyhow::bail!("unsupported control-plane envelope");
    }

    let nonce_bytes = B64
        .decode(&envelope.nonce)
        .map_err(|_| anyhow::anyhow!("invalid control-plane nonce"))?;
    if nonce_bytes.len() != NONCE_LEN {
        anyhow::bail!("invalid control-plane nonce length");
    }
    let ciphertext = B64
        .decode(&envelope.ciphertext)
        .map_err(|_| anyhow::anyhow!("invalid control-plane ciphertext"))?;

    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let decrypted = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("control-plane authentication failed"))?;
    let mut decoder = zstd::stream::read::Decoder::new(Cursor::new(decrypted))?;
    let mut raw = Vec::new();
    decoder
        .by_ref()
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_DECOMPRESSED_BYTES {
        anyhow::bail!("control-plane payload exceeds decompressed size limit");
    }
    Ok(serde_json::from_slice(&raw)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_compresses_and_authenticates() {
        let key = [7u8; KEY_LEN];
        let command = BaselineCommand {
            request_id: "test-1".to_string(),
            host_id: "host-1".to_string(),
            issued_at_ms: 1,
            expires_at_ms: 2,
            checks: vec![BaselineCheckSpec {
                id: "os".to_string(),
                kind: BaselineCheckKind::SystemInfo,
                paths: Vec::new(),
            }],
        };

        let envelope = seal_json(&command, &key).expect("seal");
        assert_ne!(envelope.ciphertext, serde_json::to_string(&command).unwrap());
        let decoded: BaselineCommand = open_json(&envelope, &key).expect("open");
        assert_eq!(decoded.request_id, command.request_id);
        assert_eq!(decoded.checks.len(), 1);
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let key = [9u8; KEY_LEN];
        let mut envelope = seal_json(&"secret", &key).expect("seal");
        envelope.ciphertext.push('A');
        assert!(open_json::<String>(&envelope, &key).is_err());
    }
}
