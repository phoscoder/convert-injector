//! Encrypted on-disk copy of the last successful fetch, used when Postgres is unreachable.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::crypto::SecretKey;

#[derive(Serialize, Deserialize)]
struct CacheFile {
    fetched_at: u64, // unix seconds
    secrets: BTreeMap<String, String>,
}

pub struct Cache {
    path: PathBuf,
    key: SecretKey,
    aad: Vec<u8>,
}

impl Cache {
    pub fn new(dir: &Path, system: &str, env: &str, public_only: bool, master: &SecretKey) -> Self {
        let suffix = if public_only { ".public" } else { "" };
        Self {
            path: dir.join(format!("{system}.{env}{suffix}.cache")),
            key: master.derive("secrets-inject cache v1"),
            aad: format!("cache/{system}/{env}{suffix}").into_bytes(),
        }
    }

    pub fn write(&self, secrets: &BTreeMap<String, String>) -> Result<()> {
        let dir = self.path.parent().expect("cache path has a parent");
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;

        let file = CacheFile { fetched_at: now(), secrets: secrets.clone() };
        let encrypted = self.key.encrypt(&serde_json::to_vec(&file)?, &self.aad);

        // Write to a temp file, then rename: a crash never leaves a half-written cache.
        let tmp = self.path.with_extension("tmp");
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(&encrypted)?;
        f.sync_all()?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Returns the secrets and how old they are, in seconds.
    pub fn read(&self) -> Result<(BTreeMap<String, String>, u64)> {
        let data = fs::read(&self.path).with_context(|| format!("no cache at {}", self.path.display()))?;
        let json = self.key.decrypt(&data, &self.aad).context("cache could not be decrypted")?;
        let file: CacheFile = serde_json::from_slice(&json)?;
        Ok((file.secrets, now().saturating_sub(file.fetched_at)))
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// SECRETS_CACHE_DIR, else ~/.cache/co-injector, else /var/cache/co-injector.
pub fn default_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return Path::new(&home).join(".cache/co-injector");
    }
    PathBuf::from("/var/cache/co-injector")
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_dir() -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!("co-injector-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn sample() -> BTreeMap<String, String> {
        BTreeMap::from([("A".into(), "1".into()), ("B".into(), "two=2".into())])
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = temp_dir();
        let key = SecretKey::generate();
        let cache = Cache::new(&dir, "backend", "production", false, &key);
        cache.write(&sample()).unwrap();
        let (secrets, age) = cache.read().unwrap();
        assert_eq!(secrets, sample());
        assert!(age < 5);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn permissions_are_restrictive_and_no_temp_file_remains() {
        let dir = temp_dir();
        let key = SecretKey::generate();
        let cache = Cache::new(&dir, "backend", "production", false, &key);
        cache.write(&sample()).unwrap();
        let file = dir.join("backend.production.cache");
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(!dir.join("backend.production.tmp").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn contents_are_not_plaintext() {
        let dir = temp_dir();
        let key = SecretKey::generate();
        Cache::new(&dir, "backend", "production", false, &key).write(&sample()).unwrap();
        let raw = fs::read(dir.join("backend.production.cache")).unwrap();
        assert!(!raw.windows(5).any(|w| w == b"two=2"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn public_cache_is_a_separate_file() {
        let dir = temp_dir();
        let key = SecretKey::generate();
        Cache::new(&dir, "frontend", "production", true, &key).write(&sample()).unwrap();
        assert!(dir.join("frontend.production.public.cache").exists());
        assert!(Cache::new(&dir, "frontend", "production", false, &key).read().is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wrong_key_or_tampering_is_rejected() {
        let dir = temp_dir();
        let key = SecretKey::generate();
        let cache = Cache::new(&dir, "backend", "production", false, &key);
        cache.write(&sample()).unwrap();
        assert!(Cache::new(&dir, "backend", "production", false, &SecretKey::generate()).read().is_err());

        let path = dir.join("backend.production.cache");
        let mut raw = fs::read(&path).unwrap();
        *raw.last_mut().unwrap() ^= 1;
        fs::write(&path, raw).unwrap();
        assert!(cache.read().is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cache_copied_to_another_system_is_rejected() {
        let dir = temp_dir();
        let key = SecretKey::generate();
        Cache::new(&dir, "backend", "production", false, &key).write(&sample()).unwrap();
        fs::copy(dir.join("backend.production.cache"), dir.join("worker.production.cache")).unwrap();
        assert!(Cache::new(&dir, "worker", "production", false, &key).read().is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_cache_is_an_error() {
        let key = SecretKey::generate();
        assert!(Cache::new(&temp_dir(), "x", "y", false, &key).read().is_err());
    }
}
