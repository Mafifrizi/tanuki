use std::fs;
use std::path::Path;

use super::types::CheckResult;
use crate::keytab::parse_keytab_bytes;
use crate::util::escape_json;

pub fn audit_keytab(keytab_path: &str) -> CheckResult {
    let p = Path::new(keytab_path);
    if !p.exists() {
        return CheckResult {
            name: "keytab_permissions".to_string(),
            status: "N_A".to_string(),
            details: format!("Keytab file not found: {}", keytab_path),
            recommendation: Some(format!("Join domain or generate keytab at {}", keytab_path)),
            remaining_seconds: None,
            extra_fields: vec![
                ("path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                ("exists".to_string(), "false".to_string()),
                ("readable".to_string(), "false".to_string()),
                ("valid_format".to_string(), "false".to_string()),
            ],
        };
    }

    #[cfg(unix)]
    let (permissions_str, is_secure_permissions, perm_status, perm_rec, perm_issue) = {
        use std::os::unix::fs::PermissionsExt;
        match fs::metadata(p) {
            Ok(meta) => {
                let mode = meta.permissions().mode();
                let octal = format!("{:04o}", mode & 0o777);
                let world_readable = (mode & 0o004) != 0;
                let world_writable = (mode & 0o002) != 0;
                let group_readable = (mode & 0o040) != 0;

                if world_readable || world_writable {
                    let desc = if world_writable { "world-writable" } else { "world-readable" };
                    (
                        octal,
                        false,
                        "FAIL",
                        Some(format!("chmod 0600 {}", keytab_path)),
                        Some(format!("Insecure permissions: {}", desc)),
                    )
                } else if group_readable {
                    (
                        octal,
                        false,
                        "WARN",
                        Some(format!("chmod 0600 {}", keytab_path)),
                        Some("Group-readable permissions conditional on service ownership".to_string()),
                    )
                } else {
                    (octal, true, "PASS", None, None)
                }
            }
            Err(e) => (
                "0000".to_string(),
                false,
                "FAIL",
                None,
                Some(format!("Failed to read metadata: {}", e)),
            ),
        }
    };

    #[cfg(not(unix))]
    let (permissions_str, is_secure_permissions, perm_status, perm_rec, perm_issue): (
        String,
        bool,
        &str,
        Option<String>,
        Option<String>,
    ) = (
        "N/A (Windows platform)".to_string(),
        true,
        "PASS",
        None,
        None,
    );

    let data = match fs::read(p) {
        Ok(bytes) => bytes,
        Err(e) => {
            return CheckResult {
                name: "keytab_permissions".to_string(),
                status: "FAIL".to_string(),
                details: format!("Read access denied: {}", e),
                recommendation: Some(format!("Ensure read permissions for {}", keytab_path)),
                remaining_seconds: None,
                extra_fields: vec![
                    ("path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                    ("exists".to_string(), "true".to_string()),
                    ("readable".to_string(), "false".to_string()),
                ],
            };
        }
    };

    if data.is_empty() {
        return CheckResult {
            name: "keytab_permissions".to_string(),
            status: "FAIL".to_string(),
            details: "Keytab file is empty (0 bytes)".to_string(),
            recommendation: Some(format!("Regenerate valid keytab at {}", keytab_path)),
            remaining_seconds: None,
            extra_fields: vec![
                ("path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                ("exists".to_string(), "true".to_string()),
                ("readable".to_string(), "true".to_string()),
                ("valid_format".to_string(), "false".to_string()),
            ],
        };
    }

    if data.len() < 2 {
        return CheckResult {
            name: "keytab_permissions".to_string(),
            status: "FAIL".to_string(),
            details: "Invalid keytab format (header < 2 bytes)".to_string(),
            recommendation: Some(format!("Regenerate valid keytab at {}", keytab_path)),
            remaining_seconds: None,
            extra_fields: vec![
                ("path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                ("exists".to_string(), "true".to_string()),
                ("readable".to_string(), "true".to_string()),
                ("valid_format".to_string(), "false".to_string()),
            ],
        };
    }

    if data[0] == 0x05 && data[1] == 0x01 {
        return CheckResult {
            name: "keytab_permissions".to_string(),
            status: "FAIL".to_string(),
            details: "Deprecated Keytab v1 format detected".to_string(),
            recommendation: Some("Upgrade keytab to Keytab v2 format".to_string()),
            remaining_seconds: None,
            extra_fields: vec![
                ("path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                ("exists".to_string(), "true".to_string()),
                ("valid_format".to_string(), "false".to_string()),
                ("format_version".to_string(), "1".to_string()),
            ],
        };
    }

    if data[0] != 0x05 || data[1] != 0x02 {
        return CheckResult {
            name: "keytab_permissions".to_string(),
            status: "FAIL".to_string(),
            details: format!(
                "Invalid keytab magic bytes (got 0x{:02x}{:02x}, expected 0x0502)",
                data[0], data[1]
            ),
            recommendation: Some(format!("Regenerate valid keytab at {}", keytab_path)),
            remaining_seconds: None,
            extra_fields: vec![
                ("path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                ("exists".to_string(), "true".to_string()),
                ("valid_format".to_string(), "false".to_string()),
            ],
        };
    }

    let parsed_entries = parse_keytab_bytes(&data);
    match parsed_entries {
        Ok(entries) => {
            let mut enctypes = Vec::new();
            let mut has_weak = false;
            for e in &entries {
                if !enctypes.contains(&e.enctype_name) {
                    enctypes.push(e.enctype_name.clone());
                }
                if matches!(e.keytype, 1 | 2 | 3 | 23) {
                    has_weak = true;
                }
            }

            let mut final_status = perm_status.to_string();
            if final_status == "PASS" && has_weak {
                final_status = "WARN".to_string();
            }

            let enctypes_summary = enctypes.join(", ");
            let perm_desc = if is_secure_permissions {
                format!("{} (secure)", permissions_str)
            } else {
                format!("{} ({})", permissions_str, perm_issue.unwrap_or_default())
            };
            let details = format!(
                "{}, Keytab v2 ({} entries, enctypes: {})",
                perm_desc,
                entries.len(),
                if enctypes_summary.is_empty() { "none" } else { &enctypes_summary }
            );

            let enctypes_json = format!(
                "[{}]",
                enctypes
                    .iter()
                    .map(|s| format!("\"{}\"", escape_json(s)))
                    .collect::<Vec<_>>()
                    .join(", ")
            );

            CheckResult {
                name: "keytab_permissions".to_string(),
                status: final_status,
                details,
                recommendation: perm_rec,
                remaining_seconds: None,
                extra_fields: vec![
                    ("path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                    ("exists".to_string(), "true".to_string()),
                    ("readable".to_string(), "true".to_string()),
                    ("valid_format".to_string(), "true".to_string()),
                    ("format_version".to_string(), "2".to_string()),
                    ("permissions".to_string(), format!("\"{}\"", escape_json(&permissions_str))),
                    ("is_secure_permissions".to_string(), is_secure_permissions.to_string()),
                    ("entry_count".to_string(), entries.len().to_string()),
                    ("encryption_types".to_string(), enctypes_json),
                    ("has_weak_enctypes".to_string(), has_weak.to_string()),
                ],
            }
        }
        Err(err) => CheckResult {
            name: "keytab_permissions".to_string(),
            status: "FAIL".to_string(),
            details: format!("Corrupted keytab: {}", err),
            recommendation: Some(format!("Re-export valid keytab to {}", keytab_path)),
            remaining_seconds: None,
            extra_fields: vec![
                ("path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                ("exists".to_string(), "true".to_string()),
                ("readable".to_string(), "true".to_string()),
                ("valid_format".to_string(), "false".to_string()),
            ],
        },
    }
}
