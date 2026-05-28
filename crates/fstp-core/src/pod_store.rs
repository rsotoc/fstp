//! Institutional pod layout with encryption at rest (AGR-101).
//!
//! Directory tree matches `agora-tickets-101-113.md`. Each JSON blob is stored as
//! `[12-byte nonce][AES-256-GCM ciphertext]`. The master key is derived via
//! Argon2id and never written to disk.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{de::DeserializeOwned, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::types::{FstpError, Result, Sha256Hash};

const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// Relative path inside the pod root (e.g. `pod/identity.json`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PodPath(pub PathBuf);

impl PodPath {
    pub fn new(relative: impl AsRef<Path>) -> Self {
        Self(relative.as_ref().to_path_buf())
    }

    pub fn identity() -> Self {
        Self::new("pod/identity.json")
    }

    pub fn sync_state() -> Self {
        Self::new("pod/sync_state.json")
    }

    pub fn roster() -> Self {
        Self::new("pod/members/roster.json")
    }

    pub fn record(id: &str) -> Self {
        Self::new(format!("pod/records/{id}.json"))
    }

    pub fn credential(id: &str) -> Self {
        Self::new(format!("pod/credentials/{id}.json"))
    }

    pub fn blocklace_frontier() -> Self {
        Self::new("pod/blocklace/frontier.json")
    }

    /// Encrypted JSON snapshot of the in-memory Blocklace (agent persistence).
    pub fn blocklace_snapshot() -> Self {
        Self::new("pod/blocklace/snapshot.json")
    }

    pub fn blocklace_block(hash_hex: &str) -> Self {
        Self::new(format!("pod/blocklace/blocks/{hash_hex}.bin"))
    }

    pub fn federation_config() -> Self {
        Self::new("config/federation.json")
    }

    pub fn sync_policy() -> Self {
        Self::new("config/sync_policy.json")
    }

    /// HU-03 / production — institutional issuers trusted for verify-credential + governance socket.
    pub fn trusted_issuers() -> Self {
        Self::new("config/trusted_issuers.json")
    }

    pub fn quorum_config() -> Self {
        Self::new("config/quorum.json")
    }

    pub fn quorum_share(share_index: u8) -> Self {
        Self::new(format!("pod/keys/quorum_share_{share_index}.enc"))
    }

    pub fn succession_record(record_id: &str) -> Self {
        Self::new(format!("pod/succession/{record_id}.json"))
    }
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Manifest {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub files: Vec<ManifestEntry>,
}

/// Encrypted read/write API for the institutional pod (AGR-101).
#[derive(Debug)]
pub struct EncryptedPodStore {
    root: PathBuf,
    key: [u8; KEY_LEN],
}

impl EncryptedPodStore {
    /// Default Modo 1 desktop data directory for the current OS.
    pub fn default_desktop_root() -> Option<PathBuf> {
        dirs::data_dir().map(|d| d.join("agora-desktop"))
    }

    /// Resolve root from `AGORA_POD_ROOT` or desktop default.
    pub fn resolve_root() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("AGORA_POD_ROOT") {
            return Ok(PathBuf::from(p));
        }
        Self::default_desktop_root()
            .ok_or_else(|| FstpError::PersistenceError("cannot resolve desktop data dir".into()))
    }

    /// Create directory layout and salt; derives key from `passphrase`.
    pub fn initialize(root: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        if root.join("keys/salt.bin").exists() {
            return Err(FstpError::PersistenceError(
                "pod already initialized — use unlock()".into(),
            ));
        }
        create_layout(&root)?;
        let salt = random_salt();
        write_salt(&root, &salt)?;
        restrict_keys_dir(&root)?;
        let key = derive_key(passphrase, &salt)?;
        Ok(Self { root, key })
    }

    /// Open an existing pod; fails with [`FstpError::InvalidCredentials`] if decryption fails.
    pub fn unlock(root: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let salt = read_salt(&root)?;
        let key = derive_key(passphrase, &salt)?;
        let store = Self {
            root: root.clone(),
            key,
        };
        store.verify_credentials()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn verify_credentials(&self) -> Result<()> {
        let marker = self.root.join("keys/.initialized");
        if !marker.exists() {
            return Ok(());
        }
        // Probe decrypt: any encrypted pod file must open with this key.
        for rel in ["pod/identity.json", "pod/sync_state.json"] {
            let path = PodPath::new(rel);
            if self.exists(&path) {
                let _: serde_json::Value = self.read(&path)?;
                return Ok(());
            }
        }
        Ok(())
    }

    fn absolute(&self, path: &PodPath) -> PathBuf {
        self.root.join(&path.0)
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| FstpError::CryptoError(e.to_string()))?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| FstpError::CryptoError(e.to_string()))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_LEN {
            return Err(FstpError::InvalidCredentials);
        }
        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| FstpError::CryptoError(e.to_string()))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| FstpError::InvalidCredentials)
    }
}

/// Public store trait (AGR-101).
pub trait PodStore {
    fn read<T: DeserializeOwned>(&self, path: &PodPath) -> Result<T>;
    fn write<T: Serialize>(&self, path: &PodPath, value: &T) -> Result<()>;
    fn exists(&self, path: &PodPath) -> bool;
    fn delete(&self, path: &PodPath) -> Result<()>;
    fn list(&self, dir: &PodPath) -> Result<Vec<PodPath>>;
    fn export_manifest(&self) -> Result<Manifest>;
}

impl PodStore for EncryptedPodStore {
    fn read<T: DeserializeOwned>(&self, path: &PodPath) -> Result<T> {
        let abs = self.absolute(path);
        let data = fs::read(&abs).map_err(FstpError::IoError)?;
        let plain = self.decrypt(&data)?;
        serde_json::from_slice(&plain).map_err(FstpError::SerializationError)
    }

    fn write<T: Serialize>(&self, path: &PodPath, value: &T) -> Result<()> {
        let abs = self.absolute(path);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent).map_err(FstpError::IoError)?;
        }
        let plain = serde_json::to_vec(value)?;
        let enc = self.encrypt(&plain)?;
        atomic_write(&abs, &enc)?;
        Ok(())
    }

    fn exists(&self, path: &PodPath) -> bool {
        self.absolute(path).is_file()
    }

    fn delete(&self, path: &PodPath) -> Result<()> {
        let abs = self.absolute(path);
        if abs.exists() {
            fs::remove_file(&abs).map_err(FstpError::IoError)?;
        }
        Ok(())
    }

    fn list(&self, dir: &PodPath) -> Result<Vec<PodPath>> {
        let abs = self.absolute(dir);
        if !abs.is_dir() {
            return Ok(Vec::new());
        }
        let prefix = dir.0.to_string_lossy().to_string();
        let mut out = Vec::new();
        for entry in fs::read_dir(&abs).map_err(FstpError::IoError)? {
            let entry = entry.map_err(FstpError::IoError)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            out.push(PodPath::new(rel));
        }
        Ok(out)
    }

    fn export_manifest(&self) -> Result<Manifest> {
        let mut files = Vec::new();
        walk_encrypted_files(&self.root, &self.root, &mut files)?;
        let mut entries = Vec::with_capacity(files.len());
        for rel in files {
            let abs = self.root.join(&rel);
            let data = fs::read(&abs).map_err(FstpError::IoError)?;
            let plain = self.decrypt(&data)?;
            let hash = Sha256Hash::digest(&plain);
            entries.push(ManifestEntry {
                path: rel,
                sha256: hash.to_hex(),
                size_bytes: plain.len() as u64,
            });
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Manifest {
            generated_at: chrono::Utc::now(),
            files: entries,
        })
    }
}

fn create_layout(root: &Path) -> Result<()> {
    let dirs = [
        "pod/credentials",
        "pod/records",
        "pod/blocklace/blocks",
        "pod/members",
        "config",
        "keys",
        "logs",
    ];
    for d in dirs {
        fs::create_dir_all(root.join(d)).map_err(FstpError::IoError)?;
    }
    fs::write(root.join("keys/.initialized"), b"1").map_err(FstpError::IoError)?;
    Ok(())
}

fn restrict_keys_dir(root: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let keys = root.join("keys");
        let mut perms = fs::metadata(&keys)
            .map_err(FstpError::IoError)?
            .permissions();
        perms.set_mode(0o700);
        fs::set_permissions(&keys, perms).map_err(FstpError::IoError)?;
    }
    Ok(())
}

fn argon2_params() -> Result<Params> {
    #[cfg(test)]
    {
        // Fast params for unit tests; production uses AGR-101 spec (64 MiB, t=3, p=4).
        Params::new(4096, 2, 1, Some(KEY_LEN)).map_err(|e| FstpError::CryptoError(e.to_string()))
    }
    #[cfg(not(test))]
    {
        Params::new(65536, 3, 4, Some(KEY_LEN)).map_err(|e| FstpError::CryptoError(e.to_string()))
    }
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let params = argon2_params()?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| FstpError::CryptoError(e.to_string()))?;
    Ok(key)
}

fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn write_salt(root: &Path, salt: &[u8]) -> Result<()> {
    fs::create_dir_all(root.join("keys")).map_err(FstpError::IoError)?;
    fs::write(root.join("keys/salt.bin"), salt).map_err(FstpError::IoError)
}

fn read_salt(root: &Path) -> Result<Vec<u8>> {
    let path = root.join("keys/salt.bin");
    if !path.exists() {
        return Err(FstpError::PersistenceError(
            "pod not initialized (missing keys/salt.bin)".into(),
        ));
    }
    fs::read(&path).map_err(FstpError::IoError)
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| FstpError::PersistenceError("path has no parent".into()))?;
    fs::create_dir_all(parent).map_err(FstpError::IoError)?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp).map_err(FstpError::IoError)?;
        f.write_all(data).map_err(FstpError::IoError)?;
        f.sync_all().map_err(FstpError::IoError)?;
    }
    fs::rename(&tmp, path).map_err(FstpError::IoError)?;
    Ok(())
}

fn walk_encrypted_files(root: &Path, base: &Path, acc: &mut Vec<String>) -> Result<()> {
    if !base.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(base).map_err(FstpError::IoError)? {
        let entry = entry.map_err(FstpError::IoError)?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "keys" || name == "logs" {
                continue;
            }
            walk_encrypted_files(root, &path, acc)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| FstpError::PersistenceError(e.to_string()))?;
            let s = rel.to_string_lossy().replace('\\', "/");
            if s.starts_with("keys/") || s.starts_with("logs/") {
                continue;
            }
            acc.push(s);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::time::Instant;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct SampleIdentity {
        did: String,
        label: String,
    }

    fn temp_root() -> PathBuf {
        let id = uuid::Uuid::new_v4();
        std::env::temp_dir().join(format!("agora-pod-test-{id}"))
    }

    #[test]
    fn init_write_reopen_roundtrip() {
        let root = temp_root();
        let _ = fs::remove_dir_all(&root);
        let store = EncryptedPodStore::initialize(&root, "test-passphrase").unwrap();
        let identity = SampleIdentity {
            did: "did:key:z6Mktest".into(),
            label: "pilot".into(),
        };
        store.write(&PodPath::identity(), &identity).unwrap();
        drop(store);

        let store2 = EncryptedPodStore::unlock(&root, "test-passphrase").unwrap();
        let loaded: SampleIdentity = store2.read(&PodPath::identity()).unwrap();
        assert_eq!(loaded, identity);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_passphrase_returns_invalid_credentials() {
        let root = temp_root();
        let _ = fs::remove_dir_all(&root);
        let store = EncryptedPodStore::initialize(&root, "correct").unwrap();
        store
            .write(
                &PodPath::identity(),
                &SampleIdentity {
                    did: "did:key:z6Mk".into(),
                    label: "x".into(),
                },
            )
            .unwrap();
        drop(store);

        assert!(matches!(
            EncryptedPodStore::unlock(&root, "wrong"),
            Err(FstpError::InvalidCredentials)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn delete_record_does_not_touch_blocklace_dir() {
        let root = temp_root();
        let _ = fs::remove_dir_all(&root);
        let store = EncryptedPodStore::initialize(&root, "pass").unwrap();
        store
            .write(&PodPath::record("acta-1"), &serde_json::json!({"hash":"abc"}))
            .unwrap();
        let block_path = root.join("pod/blocklace/blocks/deadbeef.bin");
        fs::create_dir_all(block_path.parent().unwrap()).unwrap();
        fs::write(&block_path, b"opaque-block-bytes").unwrap();

        store.delete(&PodPath::record("acta-1")).unwrap();
        assert!(!store.exists(&PodPath::record("acta-1")));
        assert!(block_path.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn export_manifest_hashes_plaintext() {
        let root = temp_root();
        let _ = fs::remove_dir_all(&root);
        let store = EncryptedPodStore::initialize(&root, "pass").unwrap();
        store
            .write(&PodPath::sync_state(), &serde_json::json!({"v":1}))
            .unwrap();
        let manifest = store.export_manifest().unwrap();
        assert!(!manifest.files.is_empty());
        assert!(manifest.files.iter().any(|e| e.path.contains("sync_state")));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn init_is_fast_on_modern_hardware() {
        let root = temp_root();
        let _ = fs::remove_dir_all(&root);
        let start = Instant::now();
        let _store = EncryptedPodStore::initialize(&root, "bench-pass").unwrap();
        assert!(
            start.elapsed().as_millis() < 500,
            "pod init took {:?}",
            start.elapsed()
        );
        let _ = fs::remove_dir_all(&root);
    }
}
