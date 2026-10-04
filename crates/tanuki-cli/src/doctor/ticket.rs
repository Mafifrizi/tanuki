use std::env;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::types::CheckResult;
use crate::util::escape_json;

struct ParsedTicket {
    default_principal: String,
    server: Option<String>,
    authtime: u32,
    endtime: u32,
    renew_till: u32,
    has_weak_enctypes: bool,
    tickets_count: usize,
    enctypes: Vec<String>,
}

fn read_principal(data: &[u8], cursor: &mut usize) -> Option<String> {
    if *cursor + 12 > data.len() {
        return None;
    }
    let num_components = u32::from_be_bytes([
        data[*cursor + 4],
        data[*cursor + 5],
        data[*cursor + 6],
        data[*cursor + 7],
    ]) as usize;
    let realm_len = u32::from_be_bytes([
        data[*cursor + 8],
        data[*cursor + 9],
        data[*cursor + 10],
        data[*cursor + 11],
    ]) as usize;
    *cursor += 12;

    if num_components > 64 || realm_len > 1024 || *cursor + realm_len > data.len() {
        return None;
    }

    let realm = String::from_utf8_lossy(&data[*cursor..*cursor + realm_len]).to_string();
    *cursor += realm_len;

    let mut components = Vec::new();
    for _ in 0..num_components {
        if *cursor + 4 > data.len() {
            return None;
        }
        let comp_len = u32::from_be_bytes([
            data[*cursor],
            data[*cursor + 1],
            data[*cursor + 2],
            data[*cursor + 3],
        ]) as usize;
        *cursor += 4;

        if comp_len > 1024 || *cursor + comp_len > data.len() {
            return None;
        }

        let comp = String::from_utf8_lossy(&data[*cursor..*cursor + comp_len]).to_string();
        *cursor += comp_len;
        components.push(comp);
    }

    if components.is_empty() {
        Some(format!("@{}", realm))
    } else {
        Some(format!("{}@{}", components.join("/"), realm))
    }
}

fn parse_ccache_bytes(data: &[u8]) -> Option<ParsedTicket> {
    if data.len() < 4 || data[0] != 0x05 || data[1] != 0x04 {
        return None;
    }

    let header_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let mut cursor = 4 + header_len;
    if cursor >= data.len() {
        return None;
    }

    let default_principal = read_principal(data, &mut cursor)?;
    let mut best_ticket: Option<ParsedTicket> = None;
    let mut has_weak_enctypes = false;
    let mut tickets_count = 0;
    let mut enctypes: Vec<String> = Vec::new();

    while cursor < data.len() {
        let _client = match read_principal(data, &mut cursor) {
            Some(c) => c,
            None => break,
        };
        let server = match read_principal(data, &mut cursor) {
            Some(s) => s,
            None => break,
        };

        if cursor + 6 > data.len() {
            break;
        }
        let enctype = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
        let key_data_len = u32::from_be_bytes([
            data[cursor + 2],
            data[cursor + 3],
            data[cursor + 4],
            data[cursor + 5],
        ]) as usize;
        cursor += 6;
        if cursor + key_data_len > data.len() {
            break;
        }
        cursor += key_data_len;
        let enc_name = crate::keytab::types::enctype_name(enctype as i16);
        if !enctypes.contains(&enc_name) {
            enctypes.push(enc_name);
        }
        if enctype == 23 || enctype == 1 || enctype == 2 || enctype == 3 {
            has_weak_enctypes = true;
        }
        tickets_count += 1;

        if cursor + 16 > data.len() {
            break;
        }
        let authtime = u32::from_be_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]);
        let _starttime = u32::from_be_bytes([
            data[cursor + 4],
            data[cursor + 5],
            data[cursor + 6],
            data[cursor + 7],
        ]);
        let endtime = u32::from_be_bytes([
            data[cursor + 8],
            data[cursor + 9],
            data[cursor + 10],
            data[cursor + 11],
        ]);
        let renew_till = u32::from_be_bytes([
            data[cursor + 12],
            data[cursor + 13],
            data[cursor + 14],
            data[cursor + 15],
        ]);
        cursor += 16;

        if cursor + 1 > data.len() {
            break;
        }
        cursor += 1;

        if cursor + 4 > data.len() {
            break;
        }
        cursor += 4;

        if cursor + 4 > data.len() {
            break;
        }
        let addr_count = u32::from_be_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]) as usize;
        cursor += 4;
        let mut addr_corrupt = false;
        for _ in 0..addr_count {
            if cursor + 6 > data.len() {
                addr_corrupt = true;
                break;
            }
            let alen = u32::from_be_bytes([
                data[cursor + 2],
                data[cursor + 3],
                data[cursor + 4],
                data[cursor + 5],
            ]) as usize;
            cursor += 6 + alen;
            if cursor > data.len() {
                addr_corrupt = true;
                break;
            }
        }
        if addr_corrupt {
            break;
        }

        if cursor + 4 > data.len() {
            break;
        }
        let ad_count = u32::from_be_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]) as usize;
        cursor += 4;
        let mut ad_corrupt = false;
        for _ in 0..ad_count {
            if cursor + 6 > data.len() {
                ad_corrupt = true;
                break;
            }
            let adlen = u32::from_be_bytes([
                data[cursor + 2],
                data[cursor + 3],
                data[cursor + 4],
                data[cursor + 5],
            ]) as usize;
            cursor += 6 + adlen;
            if cursor > data.len() {
                ad_corrupt = true;
                break;
            }
        }
        if ad_corrupt {
            break;
        }

        if cursor + 4 > data.len() {
            break;
        }
        let ticket_len = u32::from_be_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]) as usize;
        cursor += 4 + ticket_len;
        if cursor > data.len() {
            break;
        }

        if cursor + 4 > data.len() {
            break;
        }
        let sec_len = u32::from_be_bytes([
            data[cursor],
            data[cursor + 1],
            data[cursor + 2],
            data[cursor + 3],
        ]) as usize;
        cursor += 4 + sec_len;
        if cursor > data.len() {
            break;
        }

        if endtime == 0 {
            continue;
        }

        let cand = ParsedTicket {
            default_principal: default_principal.clone(),
            server: Some(server.clone()),
            authtime,
            endtime,
            renew_till,
            has_weak_enctypes,
            tickets_count,
            enctypes: enctypes.clone(),
        };

        if let Some(ref current_best) = best_ticket {
            if server.contains("krbtgt")
                && !current_best
                    .server
                    .as_deref()
                    .unwrap_or("")
                    .contains("krbtgt")
            {
                best_ticket = Some(cand);
            } else if endtime > current_best.endtime {
                best_ticket = Some(cand);
            }
        } else {
            best_ticket = Some(cand);
        }
    }

    if let Some(mut bt) = best_ticket {
        bt.has_weak_enctypes = has_weak_enctypes;
        bt.tickets_count = tickets_count;
        bt.enctypes = enctypes;
        Some(bt)
    } else {
        Some(ParsedTicket {
            default_principal,
            server: None,
            authtime: 0,
            endtime: 0,
            renew_till: 0,
            has_weak_enctypes,
            tickets_count,
            enctypes,
        })
    }
}

fn format_unix_timestamp(ts: u64) -> String {
    let secs = ts % 60;
    let mins = (ts / 60) % 60;
    let hours = (ts / 3600) % 24;
    let days = ts / 86400;

    let mut y = 1970;
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
    let mut m = 1;
    for &d in &month_days {
        if rem_days >= d {
            rem_days -= d;
            m += 1;
        } else {
            break;
        }
    }
    let d = rem_days + 1;
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, m, d, hours, mins, secs)
}

struct KeyringEntry {
    is_expired: bool,
}

fn read_proc_keys() -> Vec<KeyringEntry> {
    let mut entries = Vec::new();
    let keys_path = Path::new("/proc/keys");
    if keys_path.is_file() {
        if let Ok(content) = fs::read_to_string(keys_path) {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 8 {
                    let desc = parts[7..].join(" ");
                    let desc_lower = desc.to_ascii_lowercase();
                    if desc_lower.contains("krb") || desc_lower.contains("ccache") {
                        let flags = parts[1];
                        entries.push(KeyringEntry {
                            is_expired: flags.contains('E'),
                        });
                    }
                }
            }
        }
    }
    entries
}

pub fn audit_ticket_lifetime(custom_ccache: Option<&str>) -> CheckResult {
    let mut cache_path: Option<String> = None;
    let mut cache_type = "NONE";

    if let Some(cp) = custom_ccache {
        cache_path = Some(cp.to_string());
        cache_type = "FILE";
    } else if let Ok(env_cc) = env::var("KRB5CCNAME") {
        if env_cc.starts_with("FILE:") {
            cache_path = Some(env_cc[5..].to_string());
            cache_type = "FILE";
        } else if env_cc.starts_with('/') {
            cache_path = Some(env_cc);
            cache_type = "FILE";
        } else if env_cc.starts_with("KEYRING:") {
            cache_type = "KEYRING";
        } else if env_cc.starts_with("KCM:") {
            cache_type = "KCM";
        }
    }

    if cache_path.is_none() && cache_type == "NONE" {
        let candidates = ["/tmp/krb5cc_0", "/tmp/krb5cc_1000"];
        for c in &candidates {
            if Path::new(c).is_file() {
                cache_path = Some(c.to_string());
                cache_type = "FILE";
                break;
            }
        }
    }

    let parsed = if let Some(ref cp) = cache_path {
        match fs::read(cp) {
            Ok(bytes) => parse_ccache_bytes(&bytes),
            Err(_) => None,
        }
    } else {
        None
    };

    let keyring_keys = read_proc_keys();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    if let Some(ticket) = parsed {
        if ticket.endtime > 0 {
            let remaining = (ticket.endtime as i64) - now;
            let default_principal = ticket.default_principal;
            let service_principal = ticket.server.unwrap_or_default();
            let expiry_time = format_unix_timestamp(ticket.endtime as u64);
            let issued_time = if ticket.authtime > 0 {
                Some(format_unix_timestamp(ticket.authtime as u64))
            } else {
                None
            };
            let renew_time = if ticket.renew_till > 0 {
                Some(format_unix_timestamp(ticket.renew_till as u64))
            } else {
                None
            };

            let (mut status, is_expired, remaining_human, mut details, mut recommendation) = if remaining <= 0 {
                (
                    "EXPIRED",
                    true,
                    "Expired".to_string(),
                    format!("Principal {} expired at {}", default_principal, expiry_time),
                    Some("Acquire fresh ticket via kinit".to_string()),
                )
            } else if remaining < 1800 {
                let mins = remaining / 60;
                let secs = remaining % 60;
                let human = format!("{}m {}s", mins, secs);
                (
                    "WARN",
                    false,
                    human.clone(),
                    format!("Expiring soon: {} remaining for {}", human, default_principal),
                    Some("Renew active Kerberos ticket via kinit -R".to_string()),
                )
            } else {
                let hours = remaining / 3600;
                let mins = (remaining % 3600) / 60;
                let secs = remaining % 60;
                let human = format!("{}h {}m {}s", hours, mins, secs);
                (
                    "PASS",
                    false,
                    human.clone(),
                    format!("{} remaining for {} (expires {})", human, default_principal, expiry_time),
                    None,
                )
            };

            if ticket.has_weak_enctypes {
                if status == "PASS" {
                    status = "WARN";
                }
                details.push_str(" [WARN: Weak session key (RC4/DES) detected]");
                recommendation = Some("Enforce Kerberos AES-256 and purge weak tickets (refer to Tactical Decision Ladder Rung 2: Zero-Noise OPSEC Filter)".to_string());
            }

            return CheckResult {
                name: "ticket_lifetime".to_string(),
                status: status.to_string(),
                details,
                recommendation,
                remaining_seconds: Some(remaining),
                extra_fields: vec![
                    ("cache_type".to_string(), format!("\"{}\"", cache_type)),
                    ("cache_path".to_string(), match cache_path {
                        Some(p) => format!("\"{}\"", escape_json(&p)),
                        None => "null".to_string(),
                    }),
                    ("default_principal".to_string(), format!("\"{}\"", escape_json(&default_principal))),
                    ("service_principal".to_string(), format!("\"{}\"", escape_json(&service_principal))),
                    ("issued_time".to_string(), match issued_time {
                        Some(t) => format!("\"{}\"", escape_json(&t)),
                        None => "null".to_string(),
                    }),
                    ("expiry_time".to_string(), format!("\"{}\"", escape_json(&expiry_time))),
                    ("remaining_human".to_string(), format!("\"{}\"", escape_json(&remaining_human))),
                    ("is_expired".to_string(), is_expired.to_string()),
                    ("has_weak_enctypes".to_string(), ticket.has_weak_enctypes.to_string()),
                    ("tickets_found".to_string(), ticket.tickets_count.to_string()),
                    ("encryption_types".to_string(), format!("[{}]", ticket.enctypes.iter().map(|e| format!("\"{}\"", escape_json(e))).collect::<Vec<_>>().join(", "))),
                    ("renewable_until".to_string(), match renew_time {
                        Some(t) => format!("\"{}\"", escape_json(&t)),
                        None => "null".to_string(),
                    }),
                    ("keyring_tickets_found".to_string(), keyring_keys.len().to_string()),
                ],
            };
        }
    }

    if !keyring_keys.is_empty() {
        let active_keys: Vec<_> = keyring_keys.iter().filter(|k| !k.is_expired).collect();
        if !active_keys.is_empty() {
            CheckResult {
                name: "ticket_lifetime".to_string(),
                status: "PASS".to_string(),
                details: format!("{} active ticket keyring(s) in /proc/keys", active_keys.len()),
                recommendation: None,
                remaining_seconds: Some(0),
                extra_fields: vec![
                    ("cache_type".to_string(), "\"KEYRING\"".to_string()),
                    ("keyring_tickets_found".to_string(), keyring_keys.len().to_string()),
                ],
            }
        } else {
            CheckResult {
                name: "ticket_lifetime".to_string(),
                status: "EXPIRED".to_string(),
                details: "All Kerberos keyring tickets in /proc/keys are expired".to_string(),
                recommendation: Some("Re-authenticate using kinit".to_string()),
                remaining_seconds: Some(0),
                extra_fields: vec![
                    ("cache_type".to_string(), "\"KEYRING\"".to_string()),
                    ("keyring_tickets_found".to_string(), keyring_keys.len().to_string()),
                    ("is_expired".to_string(), "true".to_string()),
                ],
            }
        }
    } else {
        CheckResult {
            name: "ticket_lifetime".to_string(),
            status: "N_A".to_string(),
            details: "No active Kerberos tickets found in file caches or kernel keyring".to_string(),
            recommendation: Some("Run kinit to acquire Kerberos credentials".to_string()),
            remaining_seconds: Some(0),
            extra_fields: vec![
                ("cache_type".to_string(), "\"NONE\"".to_string()),
                ("cache_path".to_string(), "null".to_string()),
                ("keyring_tickets_found".to_string(), "0".to_string()),
            ],
        }
    }
}
