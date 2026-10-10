use crate::util::escape_json;
use std::fs;
use std::path::Path;

pub const KEY_USAGE_NGC: u8 = 0x01;
pub const KEY_USAGE_FIDO: u8 = 0x02;
pub const KEY_USAGE_FEK: u8 = 0x03;

pub const KEY_SOURCE_AD: u8 = 0x00;
pub const KEY_SOURCE_AZURE_AD: u8 = 0x01;

pub const ID_KEY_ID: u8 = 0x01;
pub const ID_KEY_HASH: u8 = 0x02;
pub const ID_KEY_MATERIAL: u8 = 0x03;
pub const ID_KEY_USAGE: u8 = 0x04;
pub const ID_KEY_SOURCE: u8 = 0x05;
pub const ID_DEVICE_ID: u8 = 0x06;
pub const ID_CUSTOM_KEY_INFORMATION: u8 = 0x07;
pub const ID_KEY_APPROXIMATE_LAST_LOGON_TIME: u8 = 0x08;
pub const ID_KEY_CREATION_TIME: u8 = 0x09;

fn get_identifier_name(id: u8) -> &'static str {
    match id {
        ID_KEY_ID => "KEY_ID",
        ID_KEY_HASH => "KEY_HASH",
        ID_KEY_MATERIAL => "KEY_MATERIAL",
        ID_KEY_USAGE => "KEY_USAGE",
        ID_KEY_SOURCE => "KEY_SOURCE",
        ID_DEVICE_ID => "DEVICE_ID",
        ID_CUSTOM_KEY_INFORMATION => "CUSTOM_KEY_INFORMATION",
        ID_KEY_APPROXIMATE_LAST_LOGON_TIME => "KEY_APPROXIMATE_LAST_LOGON_TIME",
        ID_KEY_CREATION_TIME => "KEY_CREATION_TIME",
        _ => "UNKNOWN_IDENTIFIER",
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

pub fn parse_filetime_to_iso(ft: u64) -> Option<String> {
    const FILETIME_TO_UNIX_OFFSET: u64 = 116_444_736_000_000_000;
    if ft < FILETIME_TO_UNIX_OFFSET {
        return None;
    }
    let ts = (ft - FILETIME_TO_UNIX_OFFSET) / 10_000_000;

    let secs = ts % 60;
    let mins = (ts / 60) % 60;
    let hours = (ts / 3600) % 24;
    let days = ts / 86400;

    let mut y = 1970u64;
    let mut rem_days = days;
    loop {
        let leap = if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) { 1 } else { 0 };
        let days_in_year = 365 + leap;
        if rem_days >= days_in_year {
            rem_days -= days_in_year;
            y += 1;
        } else {
            break;
        }
    }

    let leap = if (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0) { 1 } else { 0 };
    let month_days = [31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 1usize;
    for &d in &month_days {
        if rem_days >= d {
            rem_days -= d;
            m += 1;
        } else {
            break;
        }
    }
    let d = rem_days + 1;

    Some(format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hours, mins, secs))
}

pub fn parse_guid_bytes(data: &[u8]) -> Result<String, String> {
    if data.len() < 16 {
        return Err("Buffer underflow reading GUID".to_string());
    }
    let d1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let d2 = u16::from_le_bytes([data[4], data[5]]);
    let d3 = u16::from_le_bytes([data[6], data[7]]);
    let d4 = &data[8..16];
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyMaterialInfo {
    pub key_type: String,
    pub magic: Option<String>,
    pub bit_length: Option<u32>,
    pub public_exponent: Option<u64>,
    pub modulus_length: Option<usize>,
    pub modulus_hex: Option<String>,
    pub algorithm: Option<String>,
    pub curve: Option<String>,
    pub coordinate_length: Option<usize>,
    pub x_hex: Option<String>,
    pub y_hex: Option<String>,
    pub raw_hex: Option<String>,
}

pub fn parse_cng_public_key(data: &[u8]) -> Result<KeyMaterialInfo, String> {
    if data.len() < 8 {
        return Err(format!("Truncated CNG public key header: {} < 8 bytes", data.len()));
    }
    let magic_bytes = &data[0..4];
    let magic_str = String::from_utf8_lossy(magic_bytes).to_string();

    if magic_bytes == b"RSA1" || magic_bytes == b"RSA2" {
        if data.len() < 24 {
            return Err(format!("Truncated BCRYPT_RSAKEY_BLOB: {} < 24 bytes", data.len()));
        }
        let bit_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let cb_pub_exp = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let cb_mod = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;

        let mut offset = 24;
        if offset + cb_pub_exp + cb_mod > data.len() {
            return Err("Buffer underflow reading RSA public exponent or modulus".to_string());
        }

        let mut pub_exp = 0u64;
        for &b in &data[offset..offset + cb_pub_exp] {
            pub_exp = (pub_exp << 8) | (b as u64);
        }
        offset += cb_pub_exp;

        let modulus_bytes = &data[offset..offset + cb_mod];
        Ok(KeyMaterialInfo {
            key_type: "RSA".to_string(),
            magic: Some(magic_str),
            bit_length: Some(bit_len),
            public_exponent: Some(pub_exp),
            modulus_length: Some(cb_mod),
            modulus_hex: Some(bytes_to_hex(modulus_bytes)),
            algorithm: None,
            curve: None,
            coordinate_length: None,
            x_hex: None,
            y_hex: None,
            raw_hex: None,
        })
    } else if matches!(
        magic_bytes,
        b"ECS1" | b"ECS3" | b"ECS5" | b"ECK1" | b"ECK2" | b"ECK3" | b"ECK4" | b"ECK5" | b"ECK6"
    ) {
        let cb_key = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let offset = 8;
        if offset + (2 * cb_key) > data.len() {
            return Err("Buffer underflow reading ECC coordinates".to_string());
        }
        let x_bytes = &data[offset..offset + cb_key];
        let y_bytes = &data[offset + cb_key..offset + (2 * cb_key)];

        let curve_name = if matches!(magic_bytes, b"ECS3" | b"ECK3" | b"ECK4") {
            "P-384"
        } else if matches!(magic_bytes, b"ECS5" | b"ECK5" | b"ECK6") {
            "P-521"
        } else {
            "P-256"
        };

        let algo_name = if matches!(magic_bytes, b"ECK2" | b"ECK4" | b"ECK6") {
            "ECDH"
        } else {
            "ECDSA"
        };

        Ok(KeyMaterialInfo {
            key_type: "ECC".to_string(),
            magic: Some(magic_str),
            bit_length: None,
            public_exponent: None,
            modulus_length: None,
            modulus_hex: None,
            algorithm: Some(algo_name.to_string()),
            curve: Some(curve_name.to_string()),
            coordinate_length: Some(cb_key),
            x_hex: Some(bytes_to_hex(x_bytes)),
            y_hex: Some(bytes_to_hex(y_bytes)),
            raw_hex: None,
        })
    } else {
        Ok(KeyMaterialInfo {
            key_type: "UNKNOWN".to_string(),
            magic: Some(magic_str),
            bit_length: None,
            public_exponent: None,
            modulus_length: None,
            modulus_hex: None,
            algorithm: None,
            curve: None,
            coordinate_length: None,
            x_hex: None,
            y_hex: None,
            raw_hex: Some(bytes_to_hex(data)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomKeyInfo {
    pub version: u8,
    pub flags_raw: u8,
    pub attestation: bool,
    pub mfa_not_used: bool,
    pub extended_hex: Option<String>,
}

pub fn parse_custom_key_information(data: &[u8]) -> CustomKeyInfo {
    if data.is_empty() {
        return CustomKeyInfo {
            version: 0,
            flags_raw: 0,
            attestation: false,
            mfa_not_used: false,
            extended_hex: None,
        };
    }
    let version = data[0];
    let flags_raw = if data.len() > 1 { data[1] } else { 0 };
    let attestation = (flags_raw & 0x01) != 0;
    let mfa_not_used = (flags_raw & 0x02) != 0;
    let extended_hex = if data.len() > 2 {
        Some(bytes_to_hex(&data[2..]))
    } else {
        None
    };

    CustomKeyInfo {
        version,
        flags_raw,
        attestation,
        mfa_not_used,
        extended_hex,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEntry {
    pub identifier: u8,
    pub identifier_name: String,
    pub length: u16,
    pub raw_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowCredentialReport {
    pub status: String,
    pub version: u32,
    pub version_str: String,
    pub raw_length: usize,
    pub target_dn: Option<String>,
    pub key_id: Option<String>,
    pub key_hash: Option<String>,
    pub key_usage: Option<String>,
    pub key_source: Option<String>,
    pub device_id: Option<String>,
    pub creation_time: Option<String>,
    pub last_logon_time: Option<String>,
    pub key_material: Option<KeyMaterialInfo>,
    pub custom_key_information: Option<CustomKeyInfo>,
    pub entries_count: usize,
    pub entries: Vec<ShadowEntry>,
}

pub fn parse_key_credential_bytes(raw_bytes: &[u8], target_dn: Option<String>) -> Result<ShadowCredentialReport, String> {
    if raw_bytes.len() < 4 {
        return Err(format!("Buffer underflow: {} < 4 bytes", raw_bytes.len()));
    }
    let version = u32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]);
    if version != 0x00000100 && version != 0x00000200 {
        return Err(format!("Unsupported Key Credential version: 0x{:08x}", version));
    }

    let version_str = if version == 0x00000200 { "2.0" } else { "1.0" }.to_string();
    let mut offset = 4;
    let mut entries = Vec::new();
    let mut key_id = None;
    let mut key_hash = None;
    let mut key_usage = None;
    let mut key_source = None;
    let mut device_id = None;
    let mut creation_time = None;
    let mut last_logon_time = None;
    let mut key_material = None;
    let mut custom_key_info = None;

    while offset < raw_bytes.len() {
        if raw_bytes.len() - offset < 3 {
            return Err(format!("Truncated entry header at offset {}", offset));
        }
        let length = u16::from_le_bytes([raw_bytes[offset], raw_bytes[offset + 1]]) as usize;
        let identifier = raw_bytes[offset + 2];
        let val_start = offset + 3;
        let val_end = val_start + length;
        if val_end > raw_bytes.len() {
            return Err(format!("Entry value out of bounds: {} > {}", val_end, raw_bytes.len()));
        }
        let val_bytes = &raw_bytes[val_start..val_end];
        let id_name = get_identifier_name(identifier).to_string();

        entries.push(ShadowEntry {
            identifier,
            identifier_name: id_name,
            length: length as u16,
            raw_hex: bytes_to_hex(val_bytes),
        });

        match identifier {
            ID_KEY_ID => {
                key_id = Some(bytes_to_hex(val_bytes));
            }
            ID_KEY_HASH => {
                key_hash = Some(bytes_to_hex(val_bytes));
            }
            ID_KEY_MATERIAL => {
                if let Ok(km) = parse_cng_public_key(val_bytes) {
                    key_material = Some(km);
                }
            }
            ID_KEY_USAGE if !val_bytes.is_empty() => {
                let usage_str = match val_bytes[0] {
                    KEY_USAGE_NGC => "NGC",
                    KEY_USAGE_FIDO => "FIDO",
                    KEY_USAGE_FEK => "FEK",
                    _ => "UNKNOWN",
                };
                key_usage = Some(usage_str.to_string());
            }
            ID_KEY_SOURCE if !val_bytes.is_empty() => {
                let source_str = match val_bytes[0] {
                    KEY_SOURCE_AD => "AD",
                    KEY_SOURCE_AZURE_AD => "AzureAD",
                    _ => "UNKNOWN",
                };
                key_source = Some(source_str.to_string());
            }
            ID_DEVICE_ID if val_bytes.len() == 16 => {
                if let Ok(dev) = parse_guid_bytes(val_bytes) {
                    device_id = Some(dev);
                }
            }
            ID_CUSTOM_KEY_INFORMATION => {
                custom_key_info = Some(parse_custom_key_information(val_bytes));
            }
            ID_KEY_APPROXIMATE_LAST_LOGON_TIME if val_bytes.len() == 8 => {
                let ft = u64::from_le_bytes([
                    val_bytes[0], val_bytes[1], val_bytes[2], val_bytes[3],
                    val_bytes[4], val_bytes[5], val_bytes[6], val_bytes[7],
                ]);
                last_logon_time = parse_filetime_to_iso(ft);
            }
            ID_KEY_CREATION_TIME if val_bytes.len() == 8 => {
                let ft = u64::from_le_bytes([
                    val_bytes[0], val_bytes[1], val_bytes[2], val_bytes[3],
                    val_bytes[4], val_bytes[5], val_bytes[6], val_bytes[7],
                ]);
                creation_time = parse_filetime_to_iso(ft);
            }
            _ => {}
        }

        offset = val_end;
    }

    Ok(ShadowCredentialReport {
        status: "SUCCESS".to_string(),
        version,
        version_str,
        raw_length: raw_bytes.len(),
        target_dn,
        key_id,
        key_hash,
        key_usage,
        key_source,
        device_id,
        creation_time,
        last_logon_time,
        key_material,
        custom_key_information: custom_key_info,
        entries_count: entries.len(),
        entries,
    })
}

pub fn parse_key_credential_link(input: &str) -> Result<ShadowCredentialReport, String> {
    let clean = input.trim();
    if clean.len() < 260 && Path::new(clean).exists() {
        let data = fs::read(clean).map_err(|e| format!("Failed to read file '{}': {}", clean, e))?;
        return parse_key_credential_bytes(&data, None);
    }

    if clean.starts_with("B:") || clean.starts_with("b:") {
        let parts: Vec<&str> = clean.splitn(4, ':').collect();
        if parts.len() >= 4 {
            let char_count: usize = parts[1].parse().map_err(|_| "Invalid character count in DN-Binary".to_string())?;
            let hex_slice = if parts[2].len() > char_count {
                &parts[2][..char_count]
            } else {
                parts[2]
            };
            let mut raw_bytes = Vec::new();
            for i in (0..hex_slice.len()).step_by(2) {
                if i + 2 <= hex_slice.len() {
                    let b = u8::from_str_radix(&hex_slice[i..i + 2], 16)
                        .map_err(|_| "Invalid hex in DN-Binary".to_string())?;
                    raw_bytes.push(b);
                }
            }
            let target_dn = Some(parts[3].to_string());
            return parse_key_credential_bytes(&raw_bytes, target_dn);
        } else {
            return Err("Malformed DN-Binary string".to_string());
        }
    }

    if clean.len() % 2 == 0 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut raw_bytes = Vec::new();
        for i in (0..clean.len()).step_by(2) {
            let b = u8::from_str_radix(&clean[i..i + 2], 16)
                .map_err(|_| "Invalid hex string".to_string())?;
            raw_bytes.push(b);
        }
        return parse_key_credential_bytes(&raw_bytes, None);
    }

    Err("Input is not a readable file, valid hex string, or DN-Binary format".to_string())
}

pub fn format_shadow_report_terminal(report: &ShadowCredentialReport) -> String {
    let mut out = String::new();
    out.push_str("[+] Active Directory Shadow Credential ([MS-ADTS] 2.2.20)\n");
    out.push_str(&format!("    Structure Version : {} (0x{:08x})\n", report.version_str, report.version));
    out.push_str(&format!("    Blob Length       : {} bytes\n", report.raw_length));

    if let Some(ref dn) = report.target_dn {
        out.push_str(&format!("    Target Identity   : {}\n", dn));
    }
    if let Some(ref kid) = report.key_id {
        out.push_str(&format!("    Key ID (SHA-256)  : {}\n", kid));
    }
    if let Some(ref usage) = report.key_usage {
        out.push_str(&format!("    Key Usage         : {}\n", usage));
    }
    if let Some(ref src) = report.key_source {
        out.push_str(&format!("    Key Source        : {}\n", src));
    }
    if let Some(ref dev) = report.device_id {
        out.push_str(&format!("    Device ID (GUID)  : {}\n", dev));
    }
    if let Some(ref crt) = report.creation_time {
        out.push_str(&format!("    Creation Time     : {}\n", crt));
    }
    if let Some(ref lgt) = report.last_logon_time {
        out.push_str(&format!("    Last Logon Time   : {}\n", lgt));
    }

    if let Some(ref km) = report.key_material {
        if km.key_type == "RSA" {
            let bits = km.bit_length.unwrap_or(0);
            let exp = km.public_exponent.unwrap_or(0);
            out.push_str(&format!("    Public Key Type   : RSA ({} bits, e={})\n", bits, exp));
            if let Some(ref mod_hex) = km.modulus_hex {
                let mod_len = km.modulus_length.unwrap_or(0);
                if mod_hex.len() > 32 {
                    out.push_str(&format!("    Modulus Preview   : {}... ({} bytes)\n", &mod_hex[..32], mod_len));
                } else {
                    out.push_str(&format!("    Modulus           : {}\n", mod_hex));
                }
            }
        } else if km.key_type == "ECC" {
            let algo = km.algorithm.as_deref().unwrap_or("ECC");
            let curve = km.curve.as_deref().unwrap_or("P-256");
            out.push_str(&format!("    Public Key Type   : {} Curve {}\n", algo, curve));
            let x = km.x_hex.as_deref().unwrap_or("");
            let y = km.y_hex.as_deref().unwrap_or("");
            let x_pre = if x.len() > 16 { &x[..16] } else { x };
            let y_pre = if y.len() > 16 { &y[..16] } else { y };
            out.push_str(&format!("    Coordinates (X,Y) : X={}... Y={}...\n", x_pre, y_pre));
        }
    }

    out
}

pub fn shadow_report_to_json(report: &ShadowCredentialReport) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"status\": \"{}\",\n", escape_json(&report.status)));
    out.push_str(&format!("  \"version\": {},\n", report.version));
    out.push_str(&format!("  \"version_str\": \"{}\",\n", escape_json(&report.version_str)));
    out.push_str(&format!("  \"raw_length\": {},\n", report.raw_length));

    if let Some(ref dn) = report.target_dn {
        out.push_str(&format!("  \"target_dn\": \"{}\",\n", escape_json(dn)));
    } else {
        out.push_str("  \"target_dn\": null,\n");
    }
    if let Some(ref kid) = report.key_id {
        out.push_str(&format!("  \"key_id\": \"{}\",\n", escape_json(kid)));
    } else {
        out.push_str("  \"key_id\": null,\n");
    }
    if let Some(ref kh) = report.key_hash {
        out.push_str(&format!("  \"key_hash\": \"{}\",\n", escape_json(kh)));
    } else {
        out.push_str("  \"key_hash\": null,\n");
    }
    if let Some(ref usage) = report.key_usage {
        out.push_str(&format!("  \"key_usage\": \"{}\",\n", escape_json(usage)));
    } else {
        out.push_str("  \"key_usage\": null,\n");
    }
    if let Some(ref src) = report.key_source {
        out.push_str(&format!("  \"key_source\": \"{}\",\n", escape_json(src)));
    } else {
        out.push_str("  \"key_source\": null,\n");
    }
    if let Some(ref dev) = report.device_id {
        out.push_str(&format!("  \"device_id\": \"{}\",\n", escape_json(dev)));
    } else {
        out.push_str("  \"device_id\": null,\n");
    }
    if let Some(ref crt) = report.creation_time {
        out.push_str(&format!("  \"creation_time\": \"{}\",\n", escape_json(crt)));
    } else {
        out.push_str("  \"creation_time\": null,\n");
    }
    if let Some(ref lgt) = report.last_logon_time {
        out.push_str(&format!("  \"last_logon_time\": \"{}\",\n", escape_json(lgt)));
    } else {
        out.push_str("  \"last_logon_time\": null,\n");
    }

    if let Some(ref km) = report.key_material {
        out.push_str("  \"key_material\": {\n");
        out.push_str(&format!("    \"key_type\": \"{}\"", escape_json(&km.key_type)));
        if let Some(ref m) = km.magic {
            out.push_str(&format!(",\n    \"magic\": \"{}\"", escape_json(m)));
        }
        if let Some(b) = km.bit_length {
            out.push_str(&format!(",\n    \"bit_length\": {}", b));
        }
        if let Some(e) = km.public_exponent {
            out.push_str(&format!(",\n    \"public_exponent\": {}", e));
        }
        if let Some(ref mh) = km.modulus_hex {
            out.push_str(&format!(",\n    \"modulus_hex\": \"{}\"", escape_json(mh)));
        }
        if let Some(ref a) = km.algorithm {
            out.push_str(&format!(",\n    \"algorithm\": \"{}\"", escape_json(a)));
        }
        if let Some(ref c) = km.curve {
            out.push_str(&format!(",\n    \"curve\": \"{}\"", escape_json(c)));
        }
        out.push_str("\n  },\n");
    } else {
        out.push_str("  \"key_material\": null,\n");
    }

    out.push_str(&format!("  \"entries_count\": {}\n", report.entries_count));
    out.push('}');
    out
}
