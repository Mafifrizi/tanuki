use crate::util::escape_json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorOptions {
    pub keytab_path: Option<String>,
    pub krb5_conf_path: Option<String>,
    pub sssd_pipe: Option<String>,
    pub sssd_pid: Option<String>,
    pub ccache_path: Option<String>,
}

impl Default for DoctorOptions {
    fn default() -> Self {
        Self {
            keytab_path: Some("/etc/krb5.keytab".to_string()),
            krb5_conf_path: Some("/etc/krb5.conf".to_string()),
            sssd_pipe: Some("/var/lib/sss/pipes/kcm".to_string()),
            sssd_pid: Some("/var/run/sssd.pid".to_string()),
            ccache_path: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckResult {
    pub name: String,
    pub status: String,
    pub details: String,
    pub recommendation: Option<String>,
    pub remaining_seconds: Option<i64>,
    pub extra_fields: Vec<(String, String)>,
}

impl CheckResult {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("    {\n");
        out.push_str(&format!("      \"name\": \"{}\",\n", escape_json(&self.name)));
        out.push_str(&format!("      \"status\": \"{}\",\n", escape_json(&self.status)));
        out.push_str(&format!("      \"details\": \"{}\",\n", escape_json(&self.details)));
        match &self.recommendation {
            Some(r) => out.push_str(&format!("      \"recommendation\": \"{}\"", escape_json(r))),
            None => out.push_str("      \"recommendation\": null"),
        }
        if let Some(rem) = self.remaining_seconds {
            out.push_str(&format!(",\n      \"remaining_seconds\": {}", rem));
        }
        for (k, v) in &self.extra_fields {
            out.push_str(&format!(",\n      \"{}\": {}", escape_json(k), v));
        }
        out.push_str("\n    }");
        out
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DoctorReport {
    pub status: String,
    pub timestamp: String,
    pub duration_ms: f64,
    pub execution_time_ms: f64,
    pub passed: usize,
    pub warnings: usize,
    pub failures: usize,
    pub checks: Vec<CheckResult>,
}

impl DoctorReport {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"status\": \"{}\",\n", escape_json(&self.status)));
        out.push_str(&format!("  \"timestamp\": \"{}\",\n", escape_json(&self.timestamp)));
        out.push_str(&format!("  \"duration_ms\": {:.2},\n", self.duration_ms));
        out.push_str(&format!("  \"execution_time_ms\": {:.2},\n", self.execution_time_ms));
        out.push_str("  \"summary\": {\n");
        out.push_str(&format!("    \"passed\": {},\n", self.passed));
        out.push_str(&format!("    \"warnings\": {},\n", self.warnings));
        out.push_str(&format!("    \"failures\": {}\n", self.failures));
        out.push_str("  },\n");
        out.push_str("  \"checks\": [\n");
        let checks_json = self
            .checks
            .iter()
            .map(|c| c.to_json())
            .collect::<Vec<_>>()
            .join(",\n");
        out.push_str(&checks_json);
        out.push_str("\n  ]\n");
        out.push_str("}");
        out
    }

    pub fn format_checklist(&self) -> String {
        let mut out = String::new();
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "localhost".to_string());

        let title = "TANUKI PRE-FLIGHT DOCTOR (v1.2.1)";
        let subtitle = format!("Host: {} · Mode: Passive Diagnostic (0 network packets)", hostname);
        let width = 72;
        let t_str = format!(" {} ", title);
        let title_chars = t_str.chars().count();
        let rem = if width > title_chars + 3 { width - title_chars - 3 } else { 2 };
        out.push_str(&format!("┌──{}{}{}\n", t_str, "─".repeat(rem), "┐"));
        let sub_chars = subtitle.chars().count();
        let pad = if width > sub_chars + 4 { width - sub_chars - 4 } else { 0 };
        out.push_str(&format!("│ {}{} │\n", subtitle, " ".repeat(pad)));
        out.push_str(&format!("└{}┘\n", "─".repeat(width - 2)));

        for check in &self.checks {
            let title = match check.name.as_str() {
                "keytab_permissions" => "Keytab Integrity      ",
                "realm_capitalization" => "Kerberos Configuration",
                "sssd_subsystem" => "SSSD Subsystem        ",
                "ticket_lifetime" => "Active Ticket Cache   ",
                "host_tooling" => "Kerberos Host Tooling ",
                other => other,
            };
            out.push_str(&format!("[{}] {} : {}\n", check.status, title, check.details));
            if let Some(rec) = &check.recommendation {
                out.push_str(&format!("       Action Required        : {}\n", rec));
            }
        }

        out.push_str(&"─".repeat(72));
        out.push('\n');
        out.push_str(&format!(
            "OVERALL HEALTH: {} ({} passed, {} warnings, {} failures)\n",
            self.status, self.passed, self.warnings, self.failures
        ));
        out.push_str(&format!(
            "Execution Time: {:.2} ms | Network Packets Emitted: 0\n",
            self.duration_ms
        ));
        out.push_str(&"─".repeat(72));
        out
    }
}
