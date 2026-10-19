// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! Persistence for the key database.
//!
//! Phase 1 ships a plain-JSON file backend (written `0600`). It is a developer
//! backend only: key material is stored in the clear.
//!
//! # SECURITY
//! Do NOT use `JsonFileStore` for production key material. At-rest AEAD
//! encryption (a master-key-wrapped store via `ring`) is the next milestone and
//! will implement the same [`KeyStore`] trait, so callers do not change.

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
