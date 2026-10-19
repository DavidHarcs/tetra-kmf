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
use rand::RngCore;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// SwMI target used by the provisioning endpoints.
pub struct SwmiCfg {
    pub url: String,
    pub insecure: bool,
    pub user: String,
    pub password: String,
}

/// Console login credentials. When `None`, the console is unauthenticated
/// (localhost dev only).
pub struct Auth {
    pub user: String,
    pub password: String,
}

const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);

pub struct WebState {
    pub kmc: Mutex<Kmc<Box<dyn KeyStore>>>,
    pub swmi: Option<SwmiCfg>,
    pub auth: Option<Auth>,
    pub sessions: Mutex<HashMap<String, Instant>>,
}

impl WebState {
    pub fn new(kmc: Kmc<Box<dyn KeyStore>>, swmi: Option<SwmiCfg>, auth: Option<Auth>) -> Self {
        WebState { kmc: Mutex::new(kmc), swmi, auth, sessions: Mutex::new(HashMap::new()) }
    }

    fn new_session(&self) -> String {
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let tok = hex::encode(b);
        if let Ok(mut m) = self.sessions.lock() {
            let now = Instant::now();
            m.retain(|_, t| now.duration_since(*t) < SESSION_TTL);
            m.insert(tok.clone(), now);
        }
        tok
    }

    fn session_valid(&self, cookie_header: &str) -> bool {
        let tok = cookie_header
            .split(';')
            .find_map(|kv| kv.trim().strip_prefix("kmf_session="));
        let Some(tok) = tok else { return false };
        if let Ok(mut m) = self.sessions.lock() {
            if let Some(t) = m.get(tok).copied() {
                if Instant::now().duration_since(t) < SESSION_TTL {
                    return true;
                }
                m.remove(tok);
            }
        }
        false
    }
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

    // Headers → Content-Length + Cookie.
    let mut content_length = 0usize;
    let mut cookie_hdr = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let t = line.trim_end();
        if t.is_empty() {
            break;
        }
        let lower = t.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        } else if lower.starts_with("cookie:") {
            cookie_hdr = t.split_once(':').map(|(_, v)| v).unwrap_or("").trim().to_string();
        }
    }
    let mut body = vec![0u8; content_length.min(1 << 20)];
    if !body.is_empty() {
        reader.read_exact(&mut body)?;
    }
    let body = String::from_utf8_lossy(&body).to_string();

    // --- auth gate (when a console password is configured) ---
    if let Some(auth) = &state.auth {
        if method == "POST" && path == "/api/login" {
            let v: Value = serde_json::from_str(body.trim()).unwrap_or(Value::Null);
            if s(&v, "user") == auth.user && s(&v, "password") == auth.password {
                let tok = state.new_session();
                let ck = format!("kmf_session={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800");
                return respond_cookie(&mut stream, 200, "application/json", "{\"ok\":true}", Some(&ck));
            }
            return respond(&mut stream, 401, "application/json", "{\"ok\":false,\"error\":\"invalid login\"}");
        }
        if !state.session_valid(&cookie_hdr) {
            // Login page only for the console page; API routes get a clean 401.
            if method == "GET" && !path.starts_with("/api/") {
                return respond(&mut stream, 200, "text/html; charset=utf-8", LOGIN_HTML);
            }
            return respond(&mut stream, 401, "application/json", "{\"error\":\"unauthorized\"}");
        }
    }

    if method == "GET" && (path == "/" || path.starts_with("/index")) {
        return respond(&mut stream, 200, "text/html; charset=utf-8", INDEX_HTML);
    }
    if method == "GET" && path == "/api/state" {
        let body = state_json(state);
        return respond(&mut stream, 200, "application/json", &body);
    }
    if method == "GET" && path == "/api/keys/export" {
        let csv = {
            let kmc = state.kmc.lock().unwrap_or_else(|e| e.into_inner());
            crate::rec01::export_csv(kmc.db())
        };
        return respond(&mut stream, 200, "text/csv", &csv);
    }
    if method == "POST" && path.starts_with("/api/") {
        let v: Value = serde_json::from_str(body.trim()).unwrap_or(Value::Null);
        let (code, out) = api_post(state, &path, &v);
        return respond(&mut stream, code, "application/json", &out.to_string());
    }
    respond(&mut stream, 404, "application/json", "{\"error\":\"not found\"}")
}

fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &str) -> std::io::Result<()> {
    respond_cookie(stream, code, ctype, body, None)
}

fn respond_cookie(
    stream: &mut TcpStream,
    code: u16,
    ctype: &str,
    body: &str,
    set_cookie: Option<&str>,
) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let ck = set_cookie.map(|c| format!("Set-Cookie: {c}\r\n")).unwrap_or_default();
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nCache-Control: no-store\r\n{ck}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

const LOGIN_HTML: &str = r#"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>KMF Login</title>
<style>body{font:15px system-ui,-apple-system,Segoe UI,sans-serif;background:#1b2430;color:#fff;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}form{background:#fff;color:#1b2430;padding:24px;border-radius:10px;min-width:280px;box-shadow:0 8px 30px rgba(0,0,0,.3)}h1{font-size:16px;margin:0 0 14px}input{width:100%;padding:9px;margin:6px 0;border:1px solid #cdd5df;border-radius:6px;box-sizing:border-box}button{width:100%;padding:10px;background:#0d6efd;color:#fff;border:0;border-radius:6px;font-size:15px;cursor:pointer;margin-top:6px}.e{color:#dc3545;font-size:13px;min-height:16px}</style></head>
<body><form onsubmit="login(this);return false"><h1>&#128273; TETRA KMF Console</h1><input name=user placeholder=User value=admin autofocus><input name=password type=password placeholder=Password><div class=e id=e></div><button>Sign in</button></form>
<script>async function login(f){const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:f.user.value,password:f.password.value})});if(r.ok){location.href='/'}else{document.getElementById('e').textContent='Invalid login'}return false}</script></body></html>"#;

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
                   "tei": s.tei, "k": s.k.as_ref().map(vk)})
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
            "/api/subscriber/settei" => {
                let tei = s(v, "tei");
                let tei = if tei.is_empty() { None } else { Some(tei) };
                kmc.set_tei(u(v, "issi").unwrap_or(0) as u32, tei)?;
                Ok(json!({"ok": true}))
            }
            "/api/keys/import" => {
                let rows = crate::rec01::parse_csv(&s(v, "csv"))?;
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
                Ok(json!({"ok": true, "imported": n}))
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
