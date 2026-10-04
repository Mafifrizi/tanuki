use std::fs;
use std::path::Path;

use super::types::CheckResult;
use crate::util::escape_json;

pub fn audit_sssd(sssd_pipe: &str, sssd_pid: &str) -> CheckResult {
    let pid_candidates = [sssd_pid, "/run/sssd.pid", "/var/run/sssd.pid"];
    let mut daemon_running = false;
    let mut found_pid: Option<u32> = None;

    for pid_path in &pid_candidates {
        let p = Path::new(pid_path);
        if p.is_file() {
            if let Ok(text) = fs::read_to_string(p) {
                let trimmed = text.trim();
                if let Ok(pid) = trimmed.parse::<u32>() {
                    let proc_dir = format!("/proc/{}", pid);
                    if Path::new(&proc_dir).exists() {
                        daemon_running = true;
                        found_pid = Some(pid);
                        break;
                    }
                }
            }
        }
    }

    let sssd_footprints = ["/var/lib/sss", "/etc/sssd", "/usr/sbin/sssd", "/usr/lib/sssd"];
    let sssd_installed = sssd_footprints.iter().any(|p| Path::new(p).exists());

    if !daemon_running && sssd_installed && Path::new("/proc").is_dir() {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(fname) = entry.file_name().into_string() {
                    if fname.chars().all(|c| c.is_ascii_digit()) {
                        let comm_path = format!("/proc/{}/comm", fname);
                        if let Ok(comm) = fs::read_to_string(&comm_path) {
                            if comm.trim() == "sssd" {
                                if let Ok(pid) = fname.parse::<u32>() {
                                    daemon_running = true;
                                    found_pid = Some(pid);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let pipe_path = Path::new(sssd_pipe);
    let mut kcm_socket_active = false;

    if pipe_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if let Ok(meta) = fs::metadata(pipe_path) {
                if meta.file_type().is_socket() {
                    kcm_socket_active = true;
                }
            }
        }
        #[cfg(not(unix))]
        {
            kcm_socket_active = false;
        }
    }

    let (status, details, recommendation) = if daemon_running && kcm_socket_active {
        (
            "PASS",
            format!(
                "Active (PID {}), KCM socket available at {}",
                found_pid.unwrap_or(0),
                sssd_pipe
            ),
            None,
        )
    } else if daemon_running && !kcm_socket_active {
        (
            "WARN",
            format!(
                "SSSD running (PID {}) but KCM socket missing at {}",
                found_pid.unwrap_or(0),
                sssd_pipe
            ),
            Some("Verify KCM responder configuration in /etc/sssd/sssd.conf".to_string()),
        )
    } else if !daemon_running && kcm_socket_active {
        (
            "WARN",
            "KCM socket exists but SSSD daemon is not running".to_string(),
            Some("Start SSSD daemon: systemctl start sssd".to_string()),
        )
    } else {
        (
            "WARN",
            "SSSD daemon inactive and KCM socket not present".to_string(),
            Some("Start SSSD if host is configured for domain authentication".to_string()),
        )
    };

    let pid_json = match found_pid {
        Some(p) => p.to_string(),
        None => "null".to_string(),
    };

    CheckResult {
        name: "sssd_subsystem".to_string(),
        status: status.to_string(),
        details,
        recommendation,
        remaining_seconds: None,
        extra_fields: vec![
            ("daemon_running".to_string(), daemon_running.to_string()),
            ("pid".to_string(), pid_json),
            ("kcm_socket_path".to_string(), format!("\"{}\"", escape_json(sssd_pipe))),
            ("kcm_socket_active".to_string(), kcm_socket_active.to_string()),
        ],
    }
}
