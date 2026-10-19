// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! Append-only audit log. Every key operation is recorded as one JSON line.
//!
//! The log records *what* happened, never secret material.

use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub detail: String,
}

/// Append-only JSON-lines audit log.
pub struct AuditLog {
    path: PathBuf,
    actor: String,
}

impl AuditLog {
    pub fn new(path: impl AsRef<Path>, actor: impl Into<String>) -> Self {
        AuditLog {
            path: path.as_ref().to_path_buf(),
            actor: actor.into(),
        }
    }

    pub fn record(&self, action: &str, detail: impl Into<String>) -> Result<()> {
        let ev = AuditEvent {
            ts: Utc::now(),
            actor: self.actor.clone(),
            action: action.to_string(),
            detail: detail.into(),
        };
        let mut line = serde_json::to_string(&ev)?;
        line.push('\n');
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        f.write_all(line.as_bytes())?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
