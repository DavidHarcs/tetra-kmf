// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version. See the LICENSE file for the full terms.

//! # tetra-kmf
//!
//! An open-source **TETRA Key Management Facility (KMF)**: the authority that
//! generates, stores, versions and manages the lifecycle of TETRA key material
//! (K, SCK, GCK, GSKO, CCK per EN 300 392-7) and — in later phases — drives OTAR
//! provisioning to a TETRA SwMI such as FlowStation.
//!
//! Phase 1 (this release) provides the domain model, key store, secure
//! generation, lifecycle management, an audit log and a CLI (`kmfctl`).
//!
//! Later phases add at-rest encryption, OTAR sealing (TA41/TA51/TA52/TA81 via
//! `tetra-security`), a SwMI connector, and a web operator console.

pub mod audit;
pub mod connector;
pub mod crypto;
pub mod error;
pub mod gen;
pub mod keys;
pub mod kmc;
pub mod model;
pub mod provision;
pub mod rec01;
pub mod sealing;
pub mod store;
pub mod types;
pub mod web;

pub use error::{KmfError, Result};
pub use kmc::Kmc;
