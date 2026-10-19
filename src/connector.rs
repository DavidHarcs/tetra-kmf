// SPDX-License-Identifier: GPL-3.0-or-later
// tetra-kmf — open-source TETRA Key Management Facility
// Copyright (C) 2026 David Harcus (MM7FDM) / DonHost Media

//! SwMI connector: delivers sealed keys to a TETRA SwMI for OTAR transmission.
//!
//! [`HttpSwmiConnector`] targets a FlowStation base station's dashboard API
//! (`POST /api/otar/sck`). FlowStation transmits the D-OTAR SCK PROVIDE PDU
//! built from the sealed bytes; it holds no key material (Model B).

use crate::error::{KmfError, Result};
use crate::provision::SwmiConnector;
use crate::types::Issi;
use std::time::Duration;

/// HTTP(S) connector to a FlowStation SwMI.
pub struct HttpSwmiConnector {
    base_url: String,
    client: reqwest::blocking::Client,
}

impl HttpSwmiConnector {
    /// `base_url` e.g. `https://flowstation.local`. `insecure` accepts a
    /// self-signed TLS certificate — FlowStation ships one, which is normal on a
    /// trusted management link.
    pub fn new(base_url: impl Into<String>, insecure: bool) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(insecure)
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| KmfError::Io(format!("building HTTP client: {e}")))?;
        Ok(HttpSwmiConnector {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
        })
    }
}

impl SwmiConnector for HttpSwmiConnector {
    fn provide_sck(
        &self,
        issi: Issi,
        sckn_air: u8,
        sck_vn: u16,
        ksg_air: u8,
        ssck: &[u8],
        rso: &[u8],
    ) -> Result<String> {
        let url = format!("{}/api/otar/sck", self.base_url);
        let body = serde_json::json!({
            "issi": issi,
            "sckn_air": sckn_air,
            "sck_vn": sck_vn,
            "ksg_air": ksg_air,
            "ssck": hex::encode(ssck),
            "rso": hex::encode(rso),
        });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| KmfError::Io(format!("POST {url}: {e}")))?;
        let http_status = resp.status();
        let v: serde_json::Value = resp
            .json()
            .map_err(|e| KmfError::Io(format!("bad response from {url}: {e}")))?;
        parse_swmi_reply(&url, http_status, &v)
    }

    fn provide_gck(
        &self,
        issi: Issi,
        gckn: u16,
        gck_vn: u16,
        ksg_air: u8,
        gssi: u32,
        sgck: &[u8],
        rso: &[u8],
    ) -> Result<String> {
        let url = format!("{}/api/otar/gck", self.base_url);
        let body = serde_json::json!({
            "issi": issi,
            "gckn": gckn,
            "gck_vn": gck_vn,
            "ksg_air": ksg_air,
            "gssi": gssi,
            "sgck": hex::encode(sgck),
            "rso": hex::encode(rso),
        });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| KmfError::Io(format!("POST {url}: {e}")))?;
        let http_status = resp.status();
        let v: serde_json::Value = resp
            .json()
            .map_err(|e| KmfError::Io(format!("bad response from {url}: {e}")))?;
        parse_swmi_reply(&url, http_status, &v)
    }
}

impl HttpSwmiConnector {
    /// GET the last D-OTAR result for `issi` from the SwMI.
    pub fn result_for(&self, issi: Issi) -> Result<String> {
        let url = format!("{}/api/otar/result?issi={}", self.base_url, issi);
        let resp = self
            .client
            .get(&url)
            .send()
            .map_err(|e| KmfError::Io(format!("GET {url}: {e}")))?;
        let v: serde_json::Value = resp
            .json()
            .map_err(|e| KmfError::Io(format!("bad response from {url}: {e}")))?;
        Ok(v.get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown")
            .to_string())
    }
}

/// Interpret the SwMI's `{ok, status|error}` JSON reply.
fn parse_swmi_reply(
    url: &str,
    http_status: reqwest::StatusCode,
    v: &serde_json::Value,
) -> Result<String> {
    if v.get("ok").and_then(|b| b.as_bool()) == Some(true) {
        Ok(v.get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("accepted")
            .to_string())
    } else {
        let err = v.get("error").and_then(|s| s.as_str()).unwrap_or("rejected");
        Err(KmfError::Policy(format!(
            "SwMI rejected provision at {url} (HTTP {http_status}): {err}"
        )))
    }
}
