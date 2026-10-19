// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! Error type for the KMF.

use std::fmt;

#[derive(Debug)]
pub enum KmfError {
    /// SCK number outside the valid 1..=32 range.
    InvalidSckn(u8),
    /// Hex string could not be decoded.
    BadHex,
    /// A key had the wrong length for its kind.
    InvalidKeyLength {
        kind: &'static str,
        expected: usize,
        got: usize,
    },
    /// Requested entity does not exist.
    NotFound(String),
    /// Entity already exists.
    AlreadyExists(String),
    /// A policy / lifecycle rule was violated.
    Policy(String),
    /// Filesystem error.
    Io(String),
    /// (De)serialisation error.
    Serde(String),
}

impl fmt::Display for KmfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KmfError::InvalidSckn(n) => write!(f, "invalid SCK number {n} (must be 1..=32)"),
            KmfError::BadHex => write!(f, "invalid hex key material"),
            KmfError::InvalidKeyLength { kind, expected, got } => {
                write!(f, "{kind} key must be {expected} bytes, got {got}")
            }
            KmfError::NotFound(w) => write!(f, "not found: {w}"),
            KmfError::AlreadyExists(w) => write!(f, "already exists: {w}"),
            KmfError::Policy(w) => write!(f, "policy violation: {w}"),
            KmfError::Io(w) => write!(f, "io error: {w}"),
            KmfError::Serde(w) => write!(f, "serialisation error: {w}"),
        }
    }
}

impl std::error::Error for KmfError {}

impl From<std::io::Error> for KmfError {
    fn from(e: std::io::Error) -> Self {
        KmfError::Io(e.to_string())
    }
}

impl From<serde_json::Error> for KmfError {
    fn from(e: serde_json::Error) -> Self {
        KmfError::Serde(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, KmfError>;
