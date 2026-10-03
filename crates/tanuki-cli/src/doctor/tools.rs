use super::types::CheckResult;
use std::env;
use std::fs;
use std::path::Path;

pub fn has_binary_on_path(binary_name: &str) -> Option<String> {
    let path_var = env::var("PATH").ok()?;
    for dir in env::split_paths(&path_var) {
        let full = dir.join(binary_name);
        if full.is_file() {
            return full.to_str().map(|s| s.to_string());
        }
        #[cfg(windows)]
        {
            if !binary_name.ends_with(".exe") {
                let full_exe = dir.join(format!("{}.exe", binary_name));
                if full_exe.is_file() {
                    return full_exe.to_str().map(|s| s.to_string());
                }
            }
        }
    }
    None
}

pub fn audit_host_tools() -> CheckResult {
    let kinit_path = has_binary_on_path("kinit");
    let klist_path = has_binary_on_path("klist");
    let kvno_path = has_binary_on_path("kvno");

    let os_release_text = fs::read_to_string("/etc/os-release")
        .unwrap_or_default()
        .to_lowercase();

    let install_cmd = if os_release_text.contains("debian")
        || os_release_text.contains("ubuntu")
        || os_release_text.contains("kali")
    {
        "sudo apt install krb5-user"
    } else if os_release_text.contains("rhel")
        || os_release_text.contains("centos")
        || os_release_text.contains("fedora")
        || os_release_text.contains("rocky")
        || os_release_text.contains("alma")
    {
        "sudo dnf install krb5-workstation"
    } else if os_release_text.contains("alpine") {
        "apk add krb5"
    } else if os_release_text.contains("arch") {
        "pacman -S krb5"
    } else if cfg!(windows) {
        "Use native Windows Kerberos / PowerShell"
    } else {
        "Install krb5-user (Debian/Kali) or krb5-workstation (RHEL)"
    };

    if let Some(path) = kinit_path {
        let mut tools = vec!["kinit"];
        if klist_path.is_some() {
            tools.push("klist");
        }
        if kvno_path.is_some() {
            tools.push("kvno");
        }
        CheckResult {
            name: "host_tooling".to_string(),
            status: "PASS".to_string(),
            details: format!("Utilities available: {} (kinit: {})", tools.join(", "), path),
            recommendation: None,
            remaining_seconds: None,
            extra_fields: vec![
                ("kinit_present".to_string(), "true".to_string()),
                ("kinit_path".to_string(), format!("\"{}\"", path)),
            ],
        }
    } else {
        CheckResult {
            name: "host_tooling".to_string(),
            status: "WARN".to_string(),
            details: "Kerberos client utility ('kinit') not found on PATH".to_string(),
            recommendation: Some(format!(
                "Install client tools: {} (unprivileged: use portable client with KRB5_CONFIG)",
                install_cmd
            )),
            remaining_seconds: None,
            extra_fields: vec![
                ("kinit_present".to_string(), "false".to_string()),
                ("kinit_path".to_string(), "null".to_string()),
            ],
        }
    }
}
