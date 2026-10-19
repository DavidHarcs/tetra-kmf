// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! Persistence for the key database.
//!
//! Two backends implement [`KeyStore`]:
//! - [`EncryptedFileStore`] — AES-256-GCM at rest under a passphrase-derived
//!   key (see [`crate::crypto`]). Use this for real key material.
//! - [`JsonFileStore`] — plain JSON, written `0600`. Developer/testing only;
//!   key material is in the clear.

use crate::error::Result;
use crate::model::Database;
use std::path::{Path, PathBuf};

/// A pluggable backend that loads and saves the whole [`Database`].
pub trait KeyStore {
    fn load(&self) -> Result<Database>;
    fn save(&self, db: &Database) -> Result<()>;
}

/// Plain-JSON file backend (developer use only — see module docs).
pub struct JsonFileStore {
    path: PathBuf,
}

impl JsonFileStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        JsonFileStore {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

impl KeyStore for JsonFileStore {
    fn load(&self) -> Result<Database> {
        let bytes = std::fs::read(&self.path)?;
        let db = serde_json::from_slice(&bytes)?;
        Ok(db)
    }

    fn save(&self, db: &Database) -> Result<()> {
        let json = serde_json::to_vec_pretty(db)?;
        // Write to a temp file then rename for atomicity.
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &json)?;
        restrict_perms(&tmp)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Encrypted file backend: the database is sealed with AES-256-GCM under a key
/// derived from the operator master passphrase (see [`crate::crypto`]). This is
/// the backend to use for real key material.
pub struct EncryptedFileStore {
    path: PathBuf,
    passphrase: String,
}

impl EncryptedFileStore {
    pub fn new(path: impl AsRef<Path>, passphrase: impl Into<String>) -> Self {
        EncryptedFileStore {
            path: path.as_ref().to_path_buf(),
            passphrase: passphrase.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

impl KeyStore for EncryptedFileStore {
    fn load(&self) -> Result<Database> {
        let framed = std::fs::read(&self.path)?;
        let json = crate::crypto::open(&framed, &self.passphrase)?;
        Ok(serde_json::from_slice(&json)?)
    }

    fn save(&self, db: &Database) -> Result<()> {
        let json = serde_json::to_vec(db)?;
        let framed = crate::crypto::seal(&json, &self.passphrase)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &framed)?;
        restrict_perms(&tmp)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Lets a runtime-selected backend (`Box<dyn KeyStore>`) satisfy the generic
/// `Kmc<S: KeyStore>`.
impl KeyStore for Box<dyn KeyStore> {
    fn load(&self) -> Result<Database> {
        (**self).load()
    }

    fn save(&self, db: &Database) -> Result<()> {
        (**self).save(db)
    }
}

#[cfg(unix)]
fn restrict_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_perms(_path: &Path) -> Result<()> {
    Ok(())
}
