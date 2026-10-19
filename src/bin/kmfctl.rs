// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! `kmfctl` — command-line front end to the KMF.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use tetra_kmf::audit::AuditLog;
use tetra_kmf::store::JsonFileStore;
use tetra_kmf::types::Sckn;
use tetra_kmf::{Kmc, Result};

#[derive(Parser)]
#[command(name = "kmfctl", version, about = "TETRA Key Management Facility control tool")]
struct Cli {
    /// Path to the key database file.
    #[arg(long, global = true, default_value = "kmf-db.json")]
    db: PathBuf,
    /// Path to the append-only audit log.
    #[arg(long, global = true, default_value = "kmf-audit.jsonl")]
    audit: PathBuf,
    /// Operator name recorded in the audit log.
    #[arg(long, global = true)]
    actor: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new, empty key database.
    Init,
    /// Print a summary of the database.
    Status,
    /// Subscriber (radio) and authentication key K operations.
    Subscriber {
        #[command(subcommand)]
        cmd: SubCmd,
    },
    /// Talkgroup and group cipher key operations.
    Group {
        #[command(subcommand)]
        cmd: GroupCmd,
    },
    /// Static cipher key (SCK) slot operations.
    Sck {
        #[command(subcommand)]
        cmd: SckCmd,
    },
    /// Generate a new GSKO (group session key for OTAR) version.
    GenGsko,
}

#[derive(Subcommand)]
enum SubCmd {
    Add { issi: u32, label: String },
    List,
    GenK { issi: u32 },
    /// Print K as hex for the initial physical fill (SENSITIVE).
    ExportK { issi: u32 },
    CompromiseK { issi: u32 },
}

#[derive(Subcommand)]
enum GroupCmd {
    Add { gssi: u32, label: String },
    List,
    AddMember { gssi: u32, issi: u32 },
    GenGck { gssi: u32 },
    ActivateGck { gssi: u32, version: u16 },
}

#[derive(Subcommand)]
enum SckCmd {
    Gen {
        sckn: u8,
        #[arg(default_value = "")]
        label: String,
    },
    Activate {
        sckn: u8,
        version: u16,
    },
    List,
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let actor = cli
        .actor
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .unwrap_or_else(|| "operator".to_string());
    let audit = AuditLog::new(&cli.audit, actor);
    let store = JsonFileStore::new(&cli.db);

    // `init` creates the DB; everything else opens it.
    if matches!(cli.cmd, Cmd::Init) {
        if store.exists() {
            eprintln!("refusing to overwrite existing database {}", cli.db.display());
            return Ok(());
        }
        Kmc::init(store, audit)?;
        println!("initialised key database at {}", cli.db.display());
        return Ok(());
    }

    let mut kmc = Kmc::open(store, audit)?;

    match cli.cmd {
        Cmd::Init => unreachable!(),
        Cmd::Status => print_status(&kmc),
        Cmd::GenGsko => {
            let v = kmc.generate_gsko()?;
            println!("generated GSKO version {v} (Staged)");
        }
        Cmd::Subscriber { cmd } => match cmd {
            SubCmd::Add { issi, label } => {
                kmc.add_subscriber(issi, label)?;
                println!("added subscriber {issi}");
            }
            SubCmd::List => {
                for s in kmc.db().subscribers.values() {
                    let k = s
                        .k
                        .as_ref()
                        .map(|k| format!("K v{} {:?}", k.version, k.state))
                        .unwrap_or_else(|| "no K".to_string());
                    println!("{:>8}  {:<24} {}  [{}]", s.issi, s.label, k, if s.enabled { "enabled" } else { "disabled" });
                }
            }
            SubCmd::GenK { issi } => {
                let v = kmc.generate_k(issi)?;
                println!("generated K version {v} for subscriber {issi} (Active)");
            }
            SubCmd::ExportK { issi } => {
                let hex = kmc.export_k_hex(issi)?;
                eprintln!("!! SENSITIVE: authentication key K for {issi} follows (for fill only)");
                println!("{hex}");
            }
            SubCmd::CompromiseK { issi } => {
                kmc.compromise_k(issi)?;
                println!("flagged K for subscriber {issi} COMPROMISED");
            }
        },
        Cmd::Group { cmd } => match cmd {
            GroupCmd::Add { gssi, label } => {
                kmc.add_group(gssi, label)?;
                println!("added group {gssi}");
            }
            GroupCmd::List => {
                for g in kmc.db().groups.values() {
                    let active = g
                        .gck
                        .iter()
                        .find(|v| v.state == tetra_kmf::keys::KeyState::Active)
                        .map(|v| format!("GCK v{}", v.version))
                        .unwrap_or_else(|| "no active GCK".to_string());
                    println!(
                        "{:>8}  {:<24} {} members, {} ({} GCK versions)",
                        g.gssi,
                        g.label,
                        g.members.len(),
                        active,
                        g.gck.len()
                    );
                }
            }
            GroupCmd::AddMember { gssi, issi } => {
                kmc.add_member(gssi, issi)?;
                println!("added subscriber {issi} to group {gssi}");
            }
            GroupCmd::GenGck { gssi } => {
                let v = kmc.generate_gck(gssi)?;
                println!("generated GCK version {v} for group {gssi} (Staged)");
            }
            GroupCmd::ActivateGck { gssi, version } => {
                kmc.activate_gck(gssi, version)?;
                println!("activated GCK v{version} for group {gssi}");
            }
        },
        Cmd::Sck { cmd } => match cmd {
            SckCmd::Gen { sckn, label } => {
                let n = Sckn::new(sckn)?;
                kmc.ensure_sck_slot(n, label)?;
                let v = kmc.generate_sck(n)?;
                println!("generated SCK version {v} in slot SCKN {sckn} (Staged)");
            }
            SckCmd::Activate { sckn, version } => {
                let n = Sckn::new(sckn)?;
                kmc.activate_sck(n, version)?;
                println!("activated SCK v{version} in slot SCKN {sckn}");
            }
            SckCmd::List => {
                for slot in kmc.db().sck_slots.values() {
                    let active = slot
                        .versions
                        .iter()
                        .find(|v| v.state == tetra_kmf::keys::KeyState::Active)
                        .map(|v| format!("active v{}", v.version))
                        .unwrap_or_else(|| "none active".to_string());
                    println!(
                        "SCKN {:>2}  {:<20} {} ({} versions)",
                        slot.sckn,
                        slot.label,
                        active,
                        slot.versions.len()
                    );
                }
            }
        },
    }
    Ok(())
}

fn print_status<S: tetra_kmf::store::KeyStore>(kmc: &Kmc<S>) {
    let db = kmc.db();
    println!("TETRA KMF — database summary");
    println!("  subscribers : {}", db.subscribers.len());
    println!("  groups      : {}", db.groups.len());
    println!("  SCK slots   : {}", db.sck_slots.len());
    println!("  GSKO vers   : {}", db.gsko.len());
    println!("  CCK LAs     : {}", db.cck.len());
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
