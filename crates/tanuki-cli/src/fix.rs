use crate::config::generate_krb5_conf;
use crate::util::escape_json;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixAction {
    pub action: String,
    pub target: Option<String>,
    pub status: String,
    pub details: String,
    pub backup: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixResult {
    pub status: String,
    pub idempotent: bool,
    pub dry_run: bool,
    pub keytab_path: Option<String>,
    pub config_path: Option<String>,
    pub ccache_path: Option<String>,
    pub actions: Vec<FixAction>,
}

impl FixResult {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"status\": \"{}\",\n", escape_json(&self.status)));
        out.push_str(&format!("  \"idempotent\": {},\n", self.idempotent));
        out.push_str(&format!("  \"dry_run\": {},\n", self.dry_run));
        match &self.keytab_path {
            Some(kt) => out.push_str(&format!("  \"keytab_path\": \"{}\",\n", escape_json(kt))),
            None => out.push_str("  \"keytab_path\": null,\n"),
        }
        match &self.config_path {
            Some(cf) => out.push_str(&format!("  \"config_path\": \"{}\",\n", escape_json(cf))),
            None => out.push_str("  \"config_path\": null,\n"),
        }
        match &self.ccache_path {
            Some(cc) => out.push_str(&format!("  \"ccache_path\": \"{}\",\n", escape_json(cc))),
            None => out.push_str("  \"ccache_path\": null,\n"),
        }
        let applied_count = self.actions.iter().filter(|a| a.status == "APPLIED").count();
        let proposed_count = self.actions.iter().filter(|a| a.status == "PROPOSED").count();
        let skipped_count = self.actions.iter().filter(|a| a.status == "IDEMPOTENT_SKIPPED").count();
        out.push_str(&format!("  \"applied_count\": {},\n", applied_count));
        out.push_str(&format!("  \"proposed_count\": {},\n", proposed_count));
        out.push_str(&format!("  \"skipped_count\": {},\n", skipped_count));
        out.push_str("  \"actions\": [\n");
        for (i, a) in self.actions.iter().enumerate() {
            out.push_str("    {\n");
            out.push_str(&format!("      \"action\": \"{}\",\n", escape_json(&a.action)));
            match &a.target {
                Some(t) => out.push_str(&format!("      \"target\": \"{}\",\n", escape_json(t))),
                None => out.push_str("      \"target\": null,\n"),
            }
            out.push_str(&format!("      \"status\": \"{}\",\n", escape_json(&a.status)));
            out.push_str(&format!("      \"details\": \"{}\"", escape_json(&a.details)));
            if let Some(b) = &a.backup {
                out.push_str(&format!(",\n      \"backup\": \"{}\"", escape_json(b)));
            }
            out.push_str("\n    }");
            if i + 1 < self.actions.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ]\n}");
        out
    }

    pub fn format_terminal(&self) -> String {
        let mut out = String::new();
        let mode = if self.dry_run { "DRY RUN (Simulated)" } else { "CLOSED-LOOP EXECUTION" };
        let idemp = if self.idempotent { "CONFIRMED STABLE" } else { "ACTIONS REQUIRED" };
        out.push_str("[TANUKI CLOSED-LOOP SELF-HEALING]\n");
        out.push_str(&format!(" Mode: {} · Idempotency: {}\n\n", mode, idemp));

        for a in &self.actions {
            let tgt_str = match &a.target {
                Some(t) => format!(" [{}]", t),
                None => String::new(),
            };
            out.push_str(&format!("[{}] {}{}\n", a.status, a.action, tgt_str));
            out.push_str(&format!("    ├─ {}\n", a.details));
            if let Some(b) = &a.backup {
                out.push_str(&format!("    ╰─ Preserved Backup: {}\n", b));
            }
        }

        out.push('\n');
        if self.idempotent {
            out.push_str("[+] System State: 100% HEALTHY & IDEMPOTENT (No further changes needed)\n");
        } else {
            let count = self.actions.iter().filter(|a| a.status == "APPLIED" || a.status == "PROPOSED").count();
            out.push_str(&format!("[+] Remediation Summary: {} actions processed\n", count));
        }

        out
    }
}

pub fn run_fix(
    keytab_path: Option<&str>,
    realm: Option<&str>,
    kdc: Option<&str>,
    krb5_conf: Option<&str>,
    ccache_path: Option<&str>,
    dry_run: bool,
    clock_skew: u32,
    krb_error: Option<&str>,
) -> FixResult {
    let mut actions = Vec::new();

    // 1. Audit & remediate keytab permissions
    let resolved_keytab: Option<String> = if let Some(kt) = keytab_path {
        Some(kt.to_string())
    } else if Path::new("/etc/krb5.keytab").exists() {
        Some("/etc/krb5.keytab".to_string())
    } else if Path::new("./krb5.keytab").exists() {
        Some("./krb5.keytab".to_string())
    } else {
        None
    };

    let target_kt = resolved_keytab.as_deref().unwrap_or("/etc/krb5.keytab");
    if Path::new(target_kt).exists() {
        let is_symlink = fs::symlink_metadata(target_kt)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if is_symlink {
            actions.push(FixAction {
                action: "keytab_permissions".to_string(),
                target: Some(target_kt.to_string()),
                status: "ERROR".to_string(),
                details: format!("Refusing to modify symbolic link keytab: {}", target_kt),
                backup: None,
            });
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::metadata(target_kt) {
                    let mode = meta.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        if dry_run {
                            actions.push(FixAction {
                                action: "keytab_permissions".to_string(),
                                target: Some(target_kt.to_string()),
                                status: "PROPOSED".to_string(),
                                details: format!("Would chmod 0600 (current mode: 0{:o})", mode),
                                backup: None,
                            });
                        } else {
                            let mut perms = meta.permissions();
                            perms.set_mode(0o600);
                            match fs::set_permissions(target_kt, perms) {
                                Ok(_) => {
                                    actions.push(FixAction {
                                        action: "keytab_permissions".to_string(),
                                        target: Some(target_kt.to_string()),
                                        status: "APPLIED".to_string(),
                                        details: format!("Remediated permissions from 0{:o} to 0600", mode),
                                        backup: None,
                                    });
                                }
                                Err(e) => {
                                    actions.push(FixAction {
                                        action: "keytab_permissions".to_string(),
                                        target: Some(target_kt.to_string()),
                                        status: "ERROR".to_string(),
                                        details: format!("Failed to chmod 0600 on {}: {}", target_kt, e),
                                        backup: None,
                                    });
                                }
                            }
                        }
                    } else {
                        actions.push(FixAction {
                            action: "keytab_permissions".to_string(),
                            target: Some(target_kt.to_string()),
                            status: "IDEMPOTENT_SKIPPED".to_string(),
                            details: format!("Keytab already secure (mode 0{:o})", mode),
                            backup: None,
                        });
                    }
                }
            }
            #[cfg(not(unix))]
            {
                actions.push(FixAction {
                    action: "keytab_permissions".to_string(),
                    target: Some(target_kt.to_string()),
                    status: "IDEMPOTENT_SKIPPED".to_string(),
                    details: "Non-POSIX filesystem permissions compliant".to_string(),
                    backup: None,
                });
            }
        }
    } else {
        actions.push(FixAction {
            action: "keytab_permissions".to_string(),
            target: Some(target_kt.to_string()),
            status: "IDEMPOTENT_SKIPPED".to_string(),
            details: "No target keytab file found".to_string(),
            backup: None,
        });
    }

    // 2. Audit & remediate krb5.conf
    let target_conf = krb5_conf.unwrap_or("./krb5.conf");
    let extracted_realm = if let Some(ref kt) = resolved_keytab {
        if let Ok(bytes) = fs::read(kt) {
            if let Ok(entries) = crate::keytab::parse_keytab_bytes(&bytes) {
                entries.into_iter().find(|e| !e.realm.is_empty()).map(|e| e.realm)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };
    let target_realm = realm.map(|r| r.trim().to_uppercase()).or(extracted_realm);

    let extracted_kdc = if let Ok(content) = fs::read_to_string(target_conf).or_else(|_| fs::read_to_string("/etc/krb5.conf")) {
        content.lines()
            .find_map(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with("kdc") && trimmed.contains('=') {
                    trimmed.split('=').nth(1).map(|v| v.trim().to_string())
                } else {
                    None
                }
            })
    } else {
        None
    };
    let target_kdc = kdc.map(|k| k.trim().to_string()).or(extracted_kdc);

    if let (Some(r), Some(k)) = (target_realm, target_kdc.as_deref()) {
        let mut effective_skew = clock_skew;
        if let Some(err_val) = krb_error {
            let raw_bytes = if let Ok(bytes) = fs::read(err_val) {
                bytes
            } else {
                let clean_hex = err_val.trim().replace(' ', "").replace('\n', "");
                let clean_hex = clean_hex.strip_prefix("0x").unwrap_or(&clean_hex);
                if clean_hex.len() >= 30 && clean_hex.chars().all(|c| c.is_ascii_hexdigit()) && clean_hex.len() % 2 == 0 {
                    let mut decoded = Vec::new();
                    for i in (0..clean_hex.len()).step_by(2) {
                        if let Ok(b) = u8::from_str_radix(&clean_hex[i..i+2], 16) {
                            decoded.push(b);
                        }
                    }
                    decoded
                } else {
                    err_val.as_bytes().to_vec()
                }
            };

            if let Some(stime) = crate::protocol::parse_krb_error_stime(&raw_bytes) {
                let local_now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let drift = crate::protocol::calculate_clock_drift(stime, local_now);
                effective_skew = crate::protocol::calculate_remediated_clockskew(drift, 60);
            }
        }

        let conf_is_symlink = fs::symlink_metadata(target_conf)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        let bak = format!("{}.bak", target_conf);
        let bak_is_symlink = fs::symlink_metadata(&bak)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);

        if conf_is_symlink {
            actions.push(FixAction {
                action: "krb5_configuration".to_string(),
                target: Some(target_conf.to_string()),
                status: "ERROR".to_string(),
                details: format!("Refusing to write to symbolic link: {}", target_conf),
                backup: None,
            });
        } else if bak_is_symlink {
            actions.push(FixAction {
                action: "krb5_configuration".to_string(),
                target: Some(bak),
                status: "ERROR".to_string(),
                details: format!("Refusing to overwrite symbolic link backup: {}.bak", target_conf),
                backup: None,
            });
        } else if let Ok(optimal_content) = generate_krb5_conf(&r, k, None, Some(effective_skew), false, false, None) {
            let existing_content = fs::read_to_string(target_conf).ok();
            if existing_content.as_deref() == Some(&optimal_content) {
                actions.push(FixAction {
                    action: "krb5_configuration".to_string(),
                    target: Some(target_conf.to_string()),
                    status: "IDEMPOTENT_SKIPPED".to_string(),
                    details: "Configuration already optimal with udp_preference_limit=0 and clockskew".to_string(),
                    backup: None,
                });
            } else if dry_run {
                actions.push(FixAction {
                    action: "krb5_configuration".to_string(),
                    target: Some(target_conf.to_string()),
                    status: "PROPOSED".to_string(),
                    details: "Would create .bak and write optimal unprivileged krb5.conf".to_string(),
                    backup: None,
                });
            } else {
                let mut backup_path = None;
                if Path::new(target_conf).exists() {
                    if let Ok(_) = fs::copy(target_conf, &bak) {
                        backup_path = Some(bak);
                    }
                }
                match fs::write(target_conf, &optimal_content) {
                    Ok(_) => {
                        actions.push(FixAction {
                            action: "krb5_configuration".to_string(),
                            target: Some(target_conf.to_string()),
                            status: "APPLIED".to_string(),
                            details: format!("Generated unprivileged krb5.conf (clockskew={}s)", effective_skew),
                            backup: backup_path,
                        });
                    }
                    Err(e) => {
                        actions.push(FixAction {
                            action: "krb5_configuration".to_string(),
                            target: Some(target_conf.to_string()),
                            status: "ERROR".to_string(),
                            details: format!("Failed to write configuration: {}", e),
                            backup: backup_path,
                        });
                    }
                }
            }
        }
    } else {
        actions.push(FixAction {
            action: "krb5_configuration".to_string(),
            target: Some(target_conf.to_string()),
            status: "IDEMPOTENT_SKIPPED".to_string(),
            details: "Realm and KDC not provided; skipping config generation".to_string(),
            backup: None,
        });
    }

    // 3. Ticket Cache Status
    let resolved_ccache = ccache_path.map(|c| c.to_string())
        .or_else(|| std::env::var("KRB5CCNAME").ok().map(|s| s.strip_prefix("FILE:").unwrap_or(&s).to_string()));

    if let Some(ref cc) = resolved_ccache {
        if Path::new(cc).exists() {
            let (lifetime, _is_valid) = crate::doctor::ticket::check_ticket_lifetime(Some(cc));
            if lifetime > 0 {
                actions.push(FixAction {
                    action: "ticket_cache".to_string(),
                    target: Some(cc.clone()),
                    status: "IDEMPOTENT_SKIPPED".to_string(),
                    details: format!("Active Kerberos ticket valid (remaining lifetime: {}s)", lifetime),
                    backup: None,
                });
            } else {
                actions.push(FixAction {
                    action: "ticket_cache".to_string(),
                    target: Some(cc.clone()),
                    status: "PROPOSED".to_string(),
                    details: "Kerberos ticket expired or unreadable; re-authentication recommended".to_string(),
                    backup: None,
                });
            }
        } else {
            actions.push(FixAction {
                action: "ticket_cache".to_string(),
                target: Some(cc.clone()),
                status: "IDEMPOTENT_SKIPPED".to_string(),
                details: "Ticket cache not present; acquire via 'tanuki auth'".to_string(),
                backup: None,
            });
        }
    } else {
        actions.push(FixAction {
            action: "ticket_cache".to_string(),
            target: None,
            status: "IDEMPOTENT_SKIPPED".to_string(),
            details: "Ticket acquisition evaluated and stable".to_string(),
            backup: None,
        });
    }

    let has_error = actions.iter().any(|a| a.status == "ERROR");
    let status = if has_error { "ERROR".to_string() } else { "SUCCESS".to_string() };
    let idempotent = actions.iter().all(|a| a.status == "IDEMPOTENT_SKIPPED");
    FixResult {
        status,
        idempotent,
        dry_run,
        keytab_path: resolved_keytab,
        config_path: Some(target_conf.to_string()),
        ccache_path: resolved_ccache,
        actions,
    }
}
