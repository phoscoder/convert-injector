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

/// SECRETS_CACHE_DIR, else ~/.cache/secrets-inject, else /var/cache/secrets-inject.
pub fn default_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        return Path::new(&home).join(".cache/secrets-inject");
    }
    PathBuf::from("/var/cache/secrets-inject")
}