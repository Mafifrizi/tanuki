use super::types::CheckResult;
use std::fs;
use std::path::Path;

pub fn audit_opsec_sensors(keytab_path: &str, ccache_path: Option<&str>) -> CheckResult {
    let mut netlink_active = false;
    let mut auditd_running = false;
    let mut falco_active = false;
    let mut keytab_monitored = false;
    let mut ccache_monitored = false;
    let mut monitored_targets: Vec<String> = Vec::new();

    // 1. Audit Netlink Probe (/proc/net/netlink)
    if let Ok(content) = fs::read_to_string("/proc/net/netlink") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1] == "9" {
                netlink_active = true;
                break;
            }
        }
    }

    // 2. Auditd PID Probe (/run/auditd.pid or /var/run/auditd.pid)
    if Path::new("/run/auditd.pid").exists() || Path::new("/var/run/auditd.pid").exists() {
        auditd_running = true;
    }

    // 3. Falco Socket Probe
    if Path::new("/var/run/falco/falco.sock").exists() || Path::new("/run/falco/falco.sock").exists() {
        falco_active = true;
    }

    // 4. Audit Rules Inspection (/etc/audit/rules.d/*.rules and /etc/audit/audit.rules)
    let mut rules_content = String::new();
    if let Ok(entries) = fs::read_dir("/etc/audit/rules.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("rules") {
                if let Ok(c) = fs::read_to_string(&path) {
                    rules_content.push('\n');
                    rules_content.push_str(&c);
                }
            }
        }
    }
    if let Ok(c) = fs::read_to_string("/etc/audit/audit.rules") {
        rules_content.push('\n');
        rules_content.push_str(&c);
    }

    for line in rules_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("-w ") {
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(pos) = tokens.iter().position(|&t| t == "-w") {
                if pos + 1 < tokens.len() {
                    let watched = tokens[pos + 1];
                    if watched == keytab_path || keytab_path.starts_with(watched) {
                        keytab_monitored = true;
                        if !monitored_targets.contains(&watched.to_string()) {
                            monitored_targets.push(watched.to_string());
                        }
                    }
                    if let Some(cc) = ccache_path {
                        if watched == cc || cc.starts_with(watched) {
                            ccache_monitored = true;
                            if !monitored_targets.contains(&watched.to_string()) {
                                monitored_targets.push(watched.to_string());
                            }
                        }
                    } else if watched.contains("krb5cc") {
                        ccache_monitored = true;
                        if !monitored_targets.contains(&watched.to_string()) {
                            monitored_targets.push(watched.to_string());
                        }
                    }
                }
            }
        }
    }

    let mut extra = Vec::new();
    extra.push(("netlink_active".to_string(), netlink_active.to_string()));
    extra.push(("auditd_running".to_string(), auditd_running.to_string()));
    extra.push(("falco_active".to_string(), falco_active.to_string()));
    extra.push(("keytab_monitored".to_string(), keytab_monitored.to_string()));
    extra.push(("ccache_monitored".to_string(), ccache_monitored.to_string()));

    if keytab_monitored || ccache_monitored {
        let targets = monitored_targets.join(", ");
        CheckResult {
            name: "opsec_sensors".to_string(),
            status: "WARN".to_string(),
            details: format!("Host auditd watch rule actively monitoring credential paths: {}", targets),
            recommendation: Some("Accessing keytab or ccache will emit an Auditd kernel event. Prefer memory injection.".to_string()),
            remaining_seconds: None,
            extra_fields: extra,
        }
    } else if falco_active {
        CheckResult {
            name: "opsec_sensors".to_string(),
            status: "WARN".to_string(),
            details: "Falco daemon socket active on host; credential file syscalls may trigger alerts".to_string(),
            recommendation: Some("Verify Falco rule coverage for /etc/krb5.keytab access before reading.".to_string()),
            remaining_seconds: None,
            extra_fields: extra,
        }
    } else if auditd_running || netlink_active {
        CheckResult {
            name: "opsec_sensors".to_string(),
            status: "PASS".to_string(),
            details: "Audit daemon active, but no watch rules targeting keytab or ccache".to_string(),
            recommendation: None,
            remaining_seconds: None,
            extra_fields: extra,
        }
    } else {
        CheckResult {
            name: "opsec_sensors".to_string(),
            status: "PASS".to_string(),
            details: "No active Auditd or Falco monitoring detected on host".to_string(),
            recommendation: None,
            remaining_seconds: None,
            extra_fields: extra,
        }
    }
}
