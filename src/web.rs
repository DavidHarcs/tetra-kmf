// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! Web operator console: a dependency-free HTTP/1.1 server (std only) exposing a
//! single-page UI and a JSON API over the [`Kmc`].
//!
//! # Security
//! The console performs key management and OTAR provisioning. It has no auth of
//! its own, so it binds to `127.0.0.1` by default — run it on a trusted
//! management host (or behind a reverse proxy / SSH tunnel). Key material is
//! never exposed over the API (only versions and lifecycle state).

use crate::connector::HttpSwmiConnector;
use crate::keys::VersionedKey;
use crate::sealing::TetraSealer;
use crate::store::KeyStore;
use crate::types::Sckn;
use crate::Kmc;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;

/// SwMI target used by the provisioning endpoints.
pub struct SwmiCfg {
    pub url: String,
    pub insecure: bool,
    pub user: String,
    pub password: String,
}

pub struct WebState {
    pub kmc: Mutex<Kmc<Box<dyn KeyStore>>>,
    pub swmi: Option<SwmiCfg>,
}

/// Run the console until the process is killed. Blocking.
pub fn serve(state: WebState, bind: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind)?;
    eprintln!("tetra-kmf console on http://{bind}");
    // Sequential: a single-operator console, one request at a time, so the
    // in-memory KMC need not be Send/Sync.
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if let Err(e) = handle(stream, &state) {
            eprintln!("console request error: {e}");
        }
    }
    Ok(())
}

fn handle(mut stream: TcpStream, state: &WebState) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut req_line = String::new();
    if reader.read_line(&mut req_line)? == 0 {
        return Ok(());
    }
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    // Headers → Content-Length.
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let t = line.trim_end();
        if t.is_empty() {
            break;
        }
        if let Some(v) = t.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length.min(1 << 20)];
    if !body.is_empty() {
        reader.read_exact(&mut body)?;
    }
    let body = String::from_utf8_lossy(&body).to_string();

    if method == "GET" && (path == "/" || path.starts_with("/index")) {
        return respond(&mut stream, 200, "text/html; charset=utf-8", INDEX_HTML);
    }
    if method == "GET" && path == "/api/state" {
        let body = state_json(state);
        return respond(&mut stream, 200, "application/json", &body);
    }
    if method == "POST" && path.starts_with("/api/") {
        let v: Value = serde_json::from_str(body.trim()).unwrap_or(Value::Null);
        let (code, out) = api_post(state, &path, &v);
        return respond(&mut stream, code, "application/json", &out.to_string());
    }
    respond(&mut stream, 404, "application/json", "{\"error\":\"not found\"}")
}

fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &str) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

fn vk(v: &VersionedKey) -> Value {
    json!({"version": v.version, "state": format!("{:?}", v.state)})
}

fn state_json(state: &WebState) -> String {
    let kmc = state.kmc.lock().unwrap_or_else(|e| e.into_inner());
    let db = kmc.db();
    let subs: Vec<Value> = db
        .subscribers
        .values()
        .map(|s| {
            json!({"issi": s.issi, "label": s.label, "enabled": s.enabled,
                   "k": s.k.as_ref().map(vk)})
        })
        .collect();
    let groups: Vec<Value> = db
        .groups
        .values()
        .map(|g| {
            json!({"gssi": g.gssi, "label": g.label, "members": g.members,
                   "gck": g.gck.iter().map(vk).collect::<Vec<_>>()})
        })
        .collect();
    let scks: Vec<Value> = db
        .sck_slots
        .values()
        .map(|s| json!({"sckn": s.sckn, "label": s.label, "versions": s.versions.iter().map(vk).collect::<Vec<_>>()}))
        .collect();
    let gsko: Vec<Value> = db.gsko.iter().map(vk).collect();
    json!({
        "subscribers": subs, "groups": groups, "sck_slots": scks, "gsko": gsko,
        "swmi": state.swmi.as_ref().map(|s| s.url.clone()),
    })
    .to_string()
}

fn u(v: &Value, k: &str) -> Option<u64> {
    v.get(k).and_then(|x| x.as_u64())
}
fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn api_post(state: &WebState, path: &str, v: &Value) -> (u16, Value) {
    let mut kmc = state.kmc.lock().unwrap_or_else(|e| e.into_inner());
    let r: crate::Result<Value> = (|| {
        match path {
            "/api/subscriber/add" => {
                kmc.add_subscriber(u(v, "issi").unwrap_or(0) as u32, s(v, "label"))?;
                Ok(json!({"ok": true}))
            }
            "/api/subscriber/genk" => {
                let ver = kmc.generate_k(u(v, "issi").unwrap_or(0) as u32)?;
                Ok(json!({"ok": true, "version": ver}))
            }
            "/api/subscriber/compromisek" => {
                kmc.compromise_k(u(v, "issi").unwrap_or(0) as u32)?;
                Ok(json!({"ok": true}))
            }
            "/api/group/add" => {
                kmc.add_group(u(v, "gssi").unwrap_or(0) as u32, s(v, "label"))?;
                Ok(json!({"ok": true}))
            }
            "/api/group/member" => {
                kmc.add_member(u(v, "gssi").unwrap_or(0) as u32, u(v, "issi").unwrap_or(0) as u32)?;
                Ok(json!({"ok": true}))
            }
            "/api/group/gck" => {
                let ver = kmc.generate_gck(u(v, "gssi").unwrap_or(0) as u32)?;
                Ok(json!({"ok": true, "version": ver}))
            }
            "/api/group/gck/activate" => {
                kmc.activate_gck(u(v, "gssi").unwrap_or(0) as u32, u(v, "version").unwrap_or(0) as u16)?;
                Ok(json!({"ok": true}))
            }
            "/api/sck/gen" => {
                let n = Sckn::new(u(v, "sckn").unwrap_or(0) as u8)?;
                kmc.ensure_sck_slot(n, s(v, "label"))?;
                let ver = kmc.generate_sck(n)?;
                Ok(json!({"ok": true, "version": ver}))
            }
            "/api/sck/activate" => {
                let n = Sckn::new(u(v, "sckn").unwrap_or(0) as u8)?;
                kmc.activate_sck(n, u(v, "version").unwrap_or(0) as u16)?;
                Ok(json!({"ok": true}))
            }
            "/api/gsko/gen" => {
                let ver = kmc.generate_gsko()?;
                Ok(json!({"ok": true, "version": ver}))
            }
            "/api/provision/sck" | "/api/provision/gck" => {
                let cfg = state
                    .swmi
                    .as_ref()
                    .ok_or_else(|| crate::KmfError::Policy("no SwMI configured (start with --swmi)".into()))?;
                let conn = HttpSwmiConnector::new(&cfg.url, cfg.insecure, &cfg.user, &cfg.password)?;
                let ksg = u(v, "ksg").unwrap_or(2) as u8;
                let issi = u(v, "issi").unwrap_or(0) as u32;
                let version = u(v, "version").unwrap_or(1) as u16;
                let status = if path.ends_with("sck") {
                    let n = Sckn::new(u(v, "sckn").unwrap_or(0) as u8)?;
                    kmc.provision_sck(&TetraSealer, &conn, issi, n, version, ksg)?
                } else {
                    let gssi = u(v, "gssi").unwrap_or(0) as u32;
                    let gckn = u(v, "gckn").unwrap_or(1) as u16;
                    kmc.provision_gck(&TetraSealer, &conn, issi, gssi, version, gckn, ksg)?
                };
                Ok(json!({"ok": true, "status": status}))
            }
            _ => Err(crate::KmfError::NotFound(format!("route {path}"))),
        }
    })();
    match r {
        Ok(val) => (200, val),
        Err(e) => (400, json!({"ok": false, "error": e.to_string()})),
    }
}

const INDEX_HTML: &str = include_str!("console.html");
