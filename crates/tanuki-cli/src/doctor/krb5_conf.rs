use std::fs;
use std::path::Path;

use super::types::CheckResult;
use crate::util::escape_json;

pub fn audit_krb5_conf(krb5_conf_path: &str) -> CheckResult {
    let p = Path::new(krb5_conf_path);
    if !p.exists() {
        return CheckResult {
            name: "realm_capitalization".to_string(),
            status: "N_A".to_string(),
            details: format!("Configuration file not found: {}", krb5_conf_path),
            recommendation: Some(format!("Install krb5-user or configure {}", krb5_conf_path)),
            remaining_seconds: None,
            extra_fields: vec![
                ("path".to_string(), format!("\"{}\"", escape_json(krb5_conf_path))),
                ("exists".to_string(), "false".to_string()),
            ],
        };
    }

    let content = match fs::read_to_string(p) {
        Ok(s) => s,
        Err(e) => {
            return CheckResult {
                name: "realm_capitalization".to_string(),
                status: "FAIL".to_string(),
                details: format!("Read access denied: {}", e),
                recommendation: None,
                remaining_seconds: None,
                extra_fields: vec![
                    ("path".to_string(), format!("\"{}\"", escape_json(krb5_conf_path))),
                    ("exists".to_string(), "true".to_string()),
                ],
            };
        }
    };

    let mut current_section: Option<String> = None;
    let mut brace_depth: usize = 0;
    let mut default_realm: Option<String> = None;
    let mut realms_seen: Vec<String> = Vec::new();
    let mut lowercase_realms: Vec<String> = Vec::new();

    for line in content.lines() {
        let clean = line.split('#').next().unwrap_or("").split(';').next().unwrap_or("").trim();
        if clean.is_empty() {
            continue;
        }

        if clean.starts_with('[') && clean.ends_with(']') {
            let sec_name = clean[1..clean.len() - 1].trim().to_ascii_lowercase();
            current_section = Some(sec_name);
            brace_depth = 0;
            continue;
        }

        match current_section.as_deref() {
            Some("libdefaults") => {
                if let Some((k, v)) = clean.split_once('=') {
                    if k.trim() == "default_realm" {
                        let val = v.trim().to_string();
                        if val.chars().any(|c| c.is_ascii_lowercase())
                            && !lowercase_realms.contains(&val)
                        {
                            lowercase_realms.push(val.clone());
                        }
                        default_realm = Some(val);
                    }
                }
            }
            Some("realms") => {
                if brace_depth == 0 {
                    if let Some((left, _)) = clean.split_once('=') {
                        let cand = left.trim();
                        if !cand.is_empty() && !cand.contains('{') && !cand.contains('}') {
                            let cand_s = cand.to_string();
                            if !realms_seen.contains(&cand_s) {
                                realms_seen.push(cand_s.clone());
                            }
                            if cand.chars().any(|c| c.is_ascii_lowercase())
                                && !lowercase_realms.contains(&cand_s)
                            {
                                lowercase_realms.push(cand_s);
                            }
                        }
                    }
                }
                let open_count = clean.chars().filter(|&c| c == '{').count();
                let close_count = clean.chars().filter(|&c| c == '}').count();
                brace_depth = brace_depth.saturating_add(open_count).saturating_sub(close_count);
            }
            Some("domain_realm") => {
                if let Some((_domain, target_realm)) = clean.split_once('=') {
                    let rhs = target_realm.trim();
                    if !rhs.is_empty() {
                        let rhs_s = rhs.to_string();
                        if rhs.chars().any(|c| c.is_ascii_lowercase()) {
                            if !lowercase_realms.contains(&rhs_s) {
                                lowercase_realms.push(rhs_s);
                            }
                        } else if !realms_seen.contains(&rhs_s) {
                            realms_seen.push(rhs_s);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let default_realm_json = match &default_realm {
        Some(r) => format!("\"{}\"", escape_json(r)),
        None => "null".to_string(),
    };
    let realms_json = format!(
        "[{}]",
        realms_seen
            .iter()
            .map(|s| format!("\"{}\"", escape_json(s)))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let lowercase_json = format!(
        "[{}]",
        lowercase_realms
            .iter()
            .map(|s| format!("\"{}\"", escape_json(s)))
            .collect::<Vec<_>>()
            .join(", ")
    );

    if !lowercase_realms.is_empty() {
        CheckResult {
            name: "realm_capitalization".to_string(),
            status: "FAIL".to_string(),
            details: format!(
                "Lowercase realm detected: {} (RFC 4120 mandates uppercase)",
                lowercase_realms.join(", ")
            ),
            recommendation: Some(format!(
                "Capitalize realm names in {} to match Active Directory uppercase convention",
                krb5_conf_path
            )),
            remaining_seconds: None,
            extra_fields: vec![
                ("path".to_string(), format!("\"{}\"", escape_json(krb5_conf_path))),
                ("exists".to_string(), "true".to_string()),
                ("default_realm".to_string(), default_realm_json),
                ("is_realm_uppercase".to_string(), "false".to_string()),
                ("realms".to_string(), realms_json),
                ("lowercase_realms".to_string(), lowercase_json),
            ],
        }
    } else if let Some(def) = default_realm {
        CheckResult {
            name: "realm_capitalization".to_string(),
            status: "PASS".to_string(),
            details: format!("Default realm: {} (uppercase)", def),
            recommendation: None,
            remaining_seconds: None,
            extra_fields: vec![
                ("path".to_string(), format!("\"{}\"", escape_json(krb5_conf_path))),
                ("exists".to_string(), "true".to_string()),
                ("default_realm".to_string(), default_realm_json),
                ("is_realm_uppercase".to_string(), "true".to_string()),
                ("realms".to_string(), realms_json),
                ("lowercase_realms".to_string(), lowercase_json),
            ],
        }
    } else if !realms_seen.is_empty() {
        CheckResult {
            name: "realm_capitalization".to_string(),
            status: "PASS".to_string(),
            details: format!("Realms configured: {} (uppercase)", realms_seen.join(", ")),
            recommendation: None,
            remaining_seconds: None,
            extra_fields: vec![
                ("path".to_string(), format!("\"{}\"", escape_json(krb5_conf_path))),
                ("exists".to_string(), "true".to_string()),
                ("default_realm".to_string(), default_realm_json),
                ("is_realm_uppercase".to_string(), "true".to_string()),
                ("realms".to_string(), realms_json),
                ("lowercase_realms".to_string(), lowercase_json),
            ],
        }
    } else {
        CheckResult {
            name: "realm_capitalization".to_string(),
            status: "WARN".to_string(),
            details: "No realm definitions discovered in configuration".to_string(),
            recommendation: Some("Define default_realm in [libdefaults]".to_string()),
            remaining_seconds: None,
            extra_fields: vec![
                ("path".to_string(), format!("\"{}\"", escape_json(krb5_conf_path))),
                ("exists".to_string(), "true".to_string()),
                ("default_realm".to_string(), default_realm_json),
                ("is_realm_uppercase".to_string(), "true".to_string()),
                ("realms".to_string(), realms_json),
                ("lowercase_realms".to_string(), lowercase_json),
            ],
        }
    }
}
