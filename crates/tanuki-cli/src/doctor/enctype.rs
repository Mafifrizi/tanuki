use std::fs;
use std::path::Path;

use super::types::CheckResult;
use crate::keytab::parse_keytab_bytes;
use crate::util::escape_json;

pub fn audit_enctype_kvno(
    keytab_path: &str,
    ad_supported_enctypes: Option<u32>,
    ad_kvno: Option<u32>,
) -> CheckResult {
    let p = Path::new(keytab_path);
    if !p.exists() {
        return CheckResult {
            name: "enctype_sync".to_string(),
            status: "N_A".to_string(),
            details: format!("Keytab file not found: {}", keytab_path),
            recommendation: Some(format!("Join domain or export keytab at {}", keytab_path)),
            remaining_seconds: None,
            extra_fields: vec![
                ("keytab_path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                ("exists".to_string(), "false".to_string()),
            ],
        };
    }

    let data = match fs::read(p) {
        Ok(d) => d,
        Err(e) => {
            return CheckResult {
                name: "enctype_sync".to_string(),
                status: "N_A".to_string(),
                details: format!("Read access denied or unavailable: {}", e),
                recommendation: Some(format!("Ensure read permissions for {}", keytab_path)),
                remaining_seconds: None,
                extra_fields: vec![
                    ("keytab_path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                    ("exists".to_string(), "true".to_string()),
                ],
            };
        }
    };

    if data.len() < 2 || data[0] != 0x05 || data[1] != 0x02 {
        return CheckResult {
            name: "enctype_sync".to_string(),
            status: "N_A".to_string(),
            details: "Invalid or non-v2 keytab header".to_string(),
            recommendation: Some(format!("Regenerate valid keytab at {}", keytab_path)),
            remaining_seconds: None,
            extra_fields: vec![
                ("keytab_path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                ("exists".to_string(), "true".to_string()),
            ],
        };
    }

    let entries = match parse_keytab_bytes(&data) {
        Ok(e) => e,
        Err(err) => {
            return CheckResult {
                name: "enctype_sync".to_string(),
                status: "N_A".to_string(),
                details: format!("Failed to parse keytab entries: {}", err),
                recommendation: Some(format!("Re-export valid keytab to {}", keytab_path)),
                remaining_seconds: None,
                extra_fields: vec![
                    ("keytab_path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                    ("exists".to_string(), "true".to_string()),
                ],
            };
        }
    };

    if entries.is_empty() {
        return CheckResult {
            name: "enctype_sync".to_string(),
            status: "N_A".to_string(),
            details: "Keytab contains no entries".to_string(),
            recommendation: Some(format!("Re-export valid keytab to {}", keytab_path)),
            remaining_seconds: None,
            extra_fields: vec![
                ("keytab_path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
                ("exists".to_string(), "true".to_string()),
            ],
        };
    }

    let mut keytypes = Vec::new();
    let mut has_aes = false;
    let mut has_rc4 = false;
    let mut has_spn = false;
    let mut keytab_kvno: u32 = 0;

    for e in &entries {
        if !keytypes.contains(&e.keytype) {
            keytypes.push(e.keytype);
        }
        if matches!(e.keytype, 17 | 18) {
            has_aes = true;
        }
        if matches!(e.keytype, 1 | 2 | 3 | 23) {
            has_rc4 = true;
        }
        if e.principal.contains('/') {
            has_spn = true;
        }
        if e.vno > keytab_kvno {
            keytab_kvno = e.vno;
        }
    }

    let is_aes_only = has_aes && !has_rc4;

    let mut status = "PASS".to_string();
    let mut details = String::new();
    let mut recommendation: Option<String> = None;
    let mut kvno_mismatch = false;

    // Check 1: KVNO desynchronization
    if let Some(ad_vno) = ad_kvno {
        if keytab_kvno > 0 && ad_vno != keytab_kvno {
            kvno_mismatch = true;
            status = "FAIL".to_string();
            details = format!(
                "KVNO desynchronization detected: keytab KVNO is {} but Active Directory msDS-KeyVersionNumber is {}. Mutual authentication will fail with KRB_AP_ERR_BADKEYVER / Event 4769.",
                keytab_kvno, ad_vno
            );
            recommendation = Some(format!(
                "Re-synchronize keytab KVNO with Active Directory (ktpass -princ <SPN> -kvno {}) or update Active Directory account key.",
                ad_vno
            ));
        }
    }

    // Check 2: Missing msDS-SupportedEncryptionTypes / AES omission on SPN account
    if let Some(enctypes_mask) = ad_supported_enctypes {
        let has_ad_aes = (enctypes_mask & 0x18) != 0;
        if has_spn && is_aes_only && !has_ad_aes {
            if status == "PASS" {
                status = "WARN".to_string();
            }
            if !kvno_mismatch {
                details = "Account has SPN but lacks AES in msDS-SupportedEncryptionTypes (KDC defaults to RC4-HMAC etype 23). Presenting an AES-only keytab (etype 18) will trigger KRB_AP_ERR_NOKEY / Event 4769 failure.".to_string();
                recommendation = Some("Enable AES on Active Directory account: Set-ADUser -Identity <account> -KerberosEncryptionType AES128,AES256 (sets msDS-SupportedEncryptionTypes to 0x18) or add RC4-HMAC key to keytab.".to_string());
            }
        }
    }

    if status == "PASS" {
        if ad_supported_enctypes.is_some() && ad_kvno.is_some() {
            let enc_val = ad_supported_enctypes.unwrap_or(0);
            details = format!(
                "Active Directory msDS-SupportedEncryptionTypes (0x{:x}) supports AES; KVNO ({}) is synchronized with Active Directory.",
                enc_val, keytab_kvno
            );
        } else if is_aes_only && has_spn {
            details = format!(
                "Keytab contains {} AES-only service entries (KVNO {}). Verify Active Directory msDS-SupportedEncryptionTypes (0x18) to prevent KRB_AP_ERR_NOKEY.",
                entries.len(), keytab_kvno
            );
        } else {
            details = format!(
                "Keytab contains {} entries (KVNO {}, AES: {}, RC4: {})",
                entries.len(), keytab_kvno, has_aes, has_rc4
            );
        }
    }

    let mut extra_fields = vec![
        ("keytab_path".to_string(), format!("\"{}\"", escape_json(keytab_path))),
        ("exists".to_string(), "true".to_string()),
        ("keytab_kvno".to_string(), keytab_kvno.to_string()),
        ("is_aes_only".to_string(), is_aes_only.to_string()),
        ("has_spn".to_string(), has_spn.to_string()),
    ];

    if let Some(ak) = ad_kvno {
        extra_fields.push(("ad_kvno".to_string(), ak.to_string()));
    }
    if let Some(ase) = ad_supported_enctypes {
        extra_fields.push(("ad_supported_enctypes".to_string(), ase.to_string()));
    }

    CheckResult {
        name: "enctype_sync".to_string(),
        status,
        details,
        recommendation,
        remaining_seconds: None,
        extra_fields,
    }
}
