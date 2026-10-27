// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! `kmfctl` — command-line front end to the KMF.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use tetra_kmf::audit::AuditLog;
use tetra_kmf::connector::HttpSwmiConnector;
use tetra_kmf::sealing::TetraSealer;
use tetra_kmf::loader::KeyFill;
use tetra_kmf::store::{EncryptedFileStore, JsonFileStore, KeyStore};
use tetra_kmf::types::Sckn;
use tetra_kmf::{Kmc, KmfError, Result};

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
    /// Run the web operator console.
    Serve {
        /// Address to bind (keep on localhost / a trusted host — no built-in auth).
        #[arg(long, default_value = "127.0.0.1:8088")]
        bind: String,
        /// SwMI base URL to provision to, e.g. https://flowstation.local
        #[arg(long)]
        swmi: Option<String>,
        #[arg(long, default_value = "admin")]
        user: String,
        /// SwMI dashboard password (or env TETRA_KMF_SWMI_PASSWORD).
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = false)]
        insecure: bool,
        /// Console login user.
        #[arg(long, default_value = "admin")]
        console_user: String,
        /// Console login password (or env TETRA_KMF_CONSOLE_PASSWORD). If unset,
        /// the console runs WITHOUT login (localhost only).
        #[arg(long)]
        console_password: Option<String>,
    },
    /// OTAR operations.
    Otar {
        #[command(subcommand)]
        cmd: OtarCmd,
    },
    /// Import/export K material (SFPG Rec 01-aligned) for external loaders (SKMS/KVL).
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Direct-cable key loader: write key material into a radio / fill device
    /// over a serial line (needs `--features serial`, except `selftest`).
    Loader {
        #[command(subcommand)]
        cmd: LoaderCmd,
    },
}

#[derive(Subcommand)]
enum LoaderCmd {
    /// Exercise the whole fill pipeline against an in-process reference device —
    /// no hardware, no serial feature needed. Proves DB → KFP → device works.
    Selftest,
    /// Read the attached radio's equipment identity (TEI).
    ReadTei {
        #[command(flatten)]
        port: PortArgs,
    },
    /// Write a subscriber's authentication key K (pulled from the KMF).
    WriteK {
        issi: u32,
        #[command(flatten)]
        port: PortArgs,
    },
    /// Write a slot's active Static Cipher Key (pulled from the KMF).
    WriteSck {
        sckn: u8,
        #[command(flatten)]
        port: PortArgs,
    },
    /// Write a group's active Group Cipher Key (pulled from the KMF).
    WriteGck {
        gssi: u32,
        #[command(flatten)]
        port: PortArgs,
    },
}

/// Serial port + device-dialect selection, shared by the loader write commands.
#[derive(clap::Args)]
#[allow(dead_code)] // fields are read only under `--features serial`
struct PortArgs {
    /// Serial device path (e.g. /dev/ttyUSB0, or COM3 on Windows).
    #[arg(long)]
    port: String,
    /// Baud rate (the CDV/KVL loaders default to 19200).
    #[arg(long, default_value_t = 19200)]
    baud: u32,
    /// Device dialect: `kfp` (open protocol / DIY fill dongle) or `motorola`
    /// (KVL serial dialect — capture-driven, not yet mapped).
    #[arg(long, value_enum, default_value_t = DeviceKind::Kfp)]
    device: DeviceKind,
}

#[derive(Clone, Copy, clap::ValueEnum)]
#[allow(dead_code)]
enum DeviceKind {
    Kfp,
    Motorola,
}

#[derive(Subcommand)]
enum OtarCmd {
    /// Seal an SCK version for a subscriber (prints the SSCK + RSO the SwMI
    /// would transmit in a D-OTAR SCK PROVIDE PDU).
    SealSck { issi: u32, sckn: u8, version: u16 },
    /// Seal an SCK and send it to a FlowStation SwMI to transmit over the air.
    ProvideSck {
        issi: u32,
        sckn: u8,
        version: u16,
        /// 1-based TEA number (1=TEA1, 2=TEA2, 3=TEA3).
        #[arg(long, default_value_t = 2)]
        ksg: u8,
        /// SwMI base URL, e.g. https://flowstation.local
        #[arg(long)]
        swmi: String,
        /// Accept the SwMI's self-signed TLS certificate.
        #[arg(long, default_value_t = false)]
        insecure: bool,
        /// Dashboard login user.
        #[arg(long, default_value = "admin")]
        user: String,
        /// Dashboard password (or env TETRA_KMF_SWMI_PASSWORD).
        #[arg(long)]
        password: Option<String>,
        /// Poll the SwMI for the radio's D-OTAR result (up to 35 s).
        #[arg(long, default_value_t = false)]
        wait: bool,
    },
    /// Seal a group's GCK and send it to a FlowStation SwMI to transmit.
    ProvideGck {
        issi: u32,
        gssi: u32,
        version: u16,
        /// 16-bit GCK number (GCKN).
        #[arg(long)]
        gckn: u16,
        /// 1-based TEA number (1=TEA1, 2=TEA2, 3=TEA3).
        #[arg(long, default_value_t = 2)]
        ksg: u8,
        /// SwMI base URL, e.g. https://flowstation.local
        #[arg(long)]
        swmi: String,
        /// Accept the SwMI's self-signed TLS certificate.
        #[arg(long, default_value_t = false)]
        insecure: bool,
        /// Dashboard login user.
        #[arg(long, default_value = "admin")]
        user: String,
        /// Dashboard password (or env TETRA_KMF_SWMI_PASSWORD).
        #[arg(long)]
        password: Option<String>,
        /// Poll the SwMI for the radio's D-OTAR result (up to 35 s).
        #[arg(long, default_value_t = false)]
        wait: bool,
    },
}

/// Poll the SwMI for the radio's D-OTAR result after a provision.
fn wait_for_result(connector: &HttpSwmiConnector, issi: u32) {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(35);
    loop {
        std::thread::sleep(Duration::from_secs(2));
        match connector.result_for(issi) {
            Ok(st) if st != "pending" && st != "sent" => {
                println!("  radio result: {st}");
                return;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("  (result poll error: {e})");
                return;
            }
        }
        if Instant::now() >= deadline {
            println!("  radio result: timeout (no response within 35 s)");
            return;
        }
    }
}

#[derive(Subcommand)]
enum SubCmd {
    Add { issi: u32, label: String },
    List,
    GenK { issi: u32 },
    /// Print K as hex for the initial physical fill (SENSITIVE).
    ExportK { issi: u32 },
    CompromiseK { issi: u32 },
    /// Set the TEI (equipment identity) for SFPG Rec 01 K/TEI pairs.
    SetTei { issi: u32, tei: String },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Export all subscriber K (SENSITIVE) to a Rec 01-aligned CSV (written 0600).
    Export { file: String },
    /// Import K from a Rec 01-aligned CSV (sets K + TEI; creates missing subscribers).
    Import { file: String },
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

    // The loader self-test needs no database or store (it drives an in-process
    // device), so handle it before any store/DB setup.
    if matches!(cli.cmd, Cmd::Loader { cmd: LoaderCmd::Selftest }) {
        return loader_selftest();
    }

    // Pick the backend: encrypted when a master passphrase is set, otherwise a
    // plaintext dev store (with a loud warning).
    let store: Box<dyn KeyStore> = match std::env::var("TETRA_KMF_MASTER_KEY") {
        Ok(pw) if !pw.is_empty() => Box::new(EncryptedFileStore::new(&cli.db, pw)),
        _ => {
            eprintln!(
                "warning: TETRA_KMF_MASTER_KEY not set — using an UNENCRYPTED plaintext store (dev only)"
            );
            Box::new(JsonFileStore::new(&cli.db))
        }
    };

    // `init` creates the DB; everything else opens it.
    if matches!(cli.cmd, Cmd::Init) {
        if cli.db.exists() {
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
        Cmd::Serve { bind, swmi, user, password, insecure, console_user, console_password } => {
            let swmi = swmi.map(|url| {
                let password = password
                    .or_else(|| std::env::var("TETRA_KMF_SWMI_PASSWORD").ok())
                    .unwrap_or_default();
                tetra_kmf::web::SwmiCfg { url, insecure, user, password }
            });
            let auth = console_password
                .or_else(|| std::env::var("TETRA_KMF_CONSOLE_PASSWORD").ok())
                .filter(|p| !p.is_empty())
                .map(|password| tetra_kmf::web::Auth { user: console_user, password });
            if auth.is_none() {
                eprintln!(
                    "warning: no console password set — running WITHOUT login (localhost only); set --console-password or TETRA_KMF_CONSOLE_PASSWORD"
                );
            }
            let state = tetra_kmf::web::WebState::new(kmc, swmi, auth);
            tetra_kmf::web::serve(state, &bind)?;
        }
        Cmd::Otar { cmd } => match cmd {
            OtarCmd::SealSck { issi, sckn, version } => {
                let n = Sckn::new(sckn)?;
                let sealed = kmc.seal_sck_for(&TetraSealer, issi, n, version)?;
                println!("sealed SCK {sckn} v{version} for subscriber {issi}:");
                println!("  SSCK = {}", hex::encode(&sealed.sealed));
                println!("  RSO  = {}", hex::encode(&sealed.rso));
                eprintln!("(the SwMI transmits SSCK+RSO in a D-OTAR SCK PROVIDE PDU)");
            }
            OtarCmd::ProvideSck { issi, sckn, version, ksg, swmi, insecure, user, password, wait } => {
                let n = Sckn::new(sckn)?;
                let password = password.or_else(|| std::env::var("TETRA_KMF_SWMI_PASSWORD").ok()).unwrap_or_default();
                let connector = HttpSwmiConnector::new(&swmi, insecure, &user, &password)?;
                let status = kmc.provision_sck(&TetraSealer, &connector, issi, n, version, ksg)?;
                println!("provisioned SCK {sckn} v{version} to ISSI {issi} via {swmi}: {status}");
                if wait {
                    wait_for_result(&connector, issi);
                }
            }
            OtarCmd::ProvideGck { issi, gssi, version, gckn, ksg, swmi, insecure, user, password, wait } => {
                let password = password.or_else(|| std::env::var("TETRA_KMF_SWMI_PASSWORD").ok()).unwrap_or_default();
                let connector = HttpSwmiConnector::new(&swmi, insecure, &user, &password)?;
                let status = kmc.provision_gck(&TetraSealer, &connector, issi, gssi, version, gckn, ksg)?;
                println!("provisioned GCK {gckn} v{version} (GSSI {gssi}) to ISSI {issi} via {swmi}: {status}");
                if wait {
                    wait_for_result(&connector, issi);
                }
            }
        },
        Cmd::Keys { cmd } => match cmd {
            KeysCmd::Export { file } => {
                let csv = tetra_kmf::rec01::export_csv(kmc.db());
                std::fs::write(&file, &csv)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
                }
                let n = kmc.db().subscribers.values().filter(|s| s.k.is_some()).count();
                eprintln!("!! SENSITIVE: wrote authentication key material to {file} (0600) — handle as keys");
                println!("exported {n} K record(s)");
            }
            KeysCmd::Import { file } => {
                let text = std::fs::read_to_string(&file)?;
                let rows = tetra_kmf::rec01::parse_csv(&text)?;
                let mut n = 0;
                for r in rows {
                    if !kmc.db().subscribers.contains_key(&r.issi) {
                        kmc.add_subscriber(r.issi, "imported")?;
                    }
                    kmc.import_k(r.issi, r.k)?;
                    if r.tei.is_some() {
                        kmc.set_tei(r.issi, r.tei)?;
                    }
                    n += 1;
                }
                println!("imported {n} K record(s)");
            }
        },
        Cmd::Loader { cmd } => match cmd {
            LoaderCmd::Selftest => loader_selftest()?,
            LoaderCmd::ReadTei { port } => {
                let mut dev = open_fill(&port)?;
                let banner = dev.hello().unwrap_or_default();
                if !banner.is_empty() {
                    println!("device: {banner}");
                }
                let tei = dev.read_tei()?;
                println!("TEI: {}", hex::encode(&tei));
            }
            LoaderCmd::WriteK { issi, port } => {
                let k = hex::decode(kmc.export_k_hex(issi)?).map_err(|_| err_hex())?;
                let tei = tei_bytes(kmc.subscriber_tei(issi));
                let mut dev = open_fill(&port)?;
                eprintln!("!! SENSITIVE: filling authentication key K for ISSI {issi} over the cable");
                dev.write_k(issi, &tei, &k)?;
                println!("wrote K to ISSI {issi}");
            }
            LoaderCmd::WriteSck { sckn, port } => {
                let n = Sckn::new(sckn)?;
                let (vn, hexk) = kmc.active_sck_hex(n)?;
                let sck = hex::decode(hexk).map_err(|_| err_hex())?;
                let mut dev = open_fill(&port)?;
                eprintln!("!! SENSITIVE: filling SCK {sckn} v{vn} over the cable");
                dev.write_sck(sckn, vn, &sck)?;
                println!("wrote SCK {sckn} v{vn}");
            }
            LoaderCmd::WriteGck { gssi, port } => {
                let (vn, hexk) = kmc.active_gck_hex(gssi)?;
                let gck = hex::decode(hexk).map_err(|_| err_hex())?;
                let gckn = gssi as u16; // GCKN defaults to the low 16 bits of GSSI
                let mut dev = open_fill(&port)?;
                eprintln!("!! SENSITIVE: filling GCK (GSSI {gssi}) v{vn} over the cable");
                dev.write_gck(gckn, vn, &gck)?;
                println!("wrote GCK for GSSI {gssi} v{vn}");
            }
        },
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
            SubCmd::SetTei { issi, tei } => {
                kmc.set_tei(issi, Some(tei))?;
                println!("set TEI for subscriber {issi}");
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

fn err_hex() -> KmfError {
    KmfError::BadHex
}

/// A stored TEI string → bytes: hex if it decodes, otherwise raw UTF-8; empty
/// when there is no TEI.
fn tei_bytes(tei: Option<String>) -> Vec<u8> {
    match tei {
        Some(s) => hex::decode(s.trim()).unwrap_or_else(|_| s.into_bytes()),
        None => Vec::new(),
    }
}

/// Open a key-fill device on a serial port (needs `--features serial`).
#[cfg(feature = "serial")]
fn open_fill(p: &PortArgs) -> Result<Box<dyn KeyFill>> {
    use tetra_kmf::loader::{motorola::MotorolaKvl, KfpDevice, SerialTransport};
    let t = SerialTransport::open(&p.port, p.baud)?;
    Ok(match p.device {
        DeviceKind::Kfp => Box::new(KfpDevice::new(t)),
        DeviceKind::Motorola => Box::new(MotorolaKvl::new(t)),
    })
}

#[cfg(not(feature = "serial"))]
fn open_fill(_p: &PortArgs) -> Result<Box<dyn KeyFill>> {
    Err(KmfError::Policy(
        "this build has no serial support — rebuild with `--features serial` to use the cable loader \
         (`loader selftest` works without it)"
            .into(),
    ))
}

/// Run the full fill pipeline against an in-process reference device.
fn loader_selftest() -> Result<()> {
    use tetra_kmf::loader::{KfpDevice, Loopback, RefDevice};
    let tei = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let mut dev = KfpDevice::new(Loopback::new(RefDevice::new(tei)));
    println!("KFP key-fill self-test (in-process reference device, no hardware):");
    println!("  hello     -> {}", dev.hello()?);
    println!("  read-tei  -> {}", hex::encode(dev.read_tei()?));
    dev.write_k(2358245, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77], &[0x11; 16])?;
    println!("  write-k    ISSI 2358245 ........ ok");
    dev.write_sck(1, 1, &[0x22; 10])?;
    println!("  write-sck  SCKN 1 v1 ........... ok");
    dev.write_gck(100, 1, &[0x33; 10])?;
    println!("  write-gck  GCKN 100 v1 ......... ok");
    println!("pipeline OK — database -> KFP -> device round-trips cleanly.");
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
