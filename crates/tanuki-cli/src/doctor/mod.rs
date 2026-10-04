pub mod keytab;
pub mod krb5_conf;
pub mod opsec;
pub mod sssd;
pub mod ticket;
pub mod tools;
pub mod types;

pub use types::{CheckResult, DoctorOptions, DoctorReport};

use std::time::Instant;

pub fn run_doctor(opts: &DoctorOptions) -> DoctorReport {
    let start = Instant::now();

    let keytab_path = opts
        .keytab_path
        .as_deref()
        .unwrap_or("/etc/krb5.keytab");
    let env_krb5_conf = std::env::var("KRB5_CONFIG").ok();
    let krb5_conf_path = opts
        .krb5_conf_path
        .as_deref()
        .or(env_krb5_conf.as_deref())
        .unwrap_or("/etc/krb5.conf");
    let sssd_pipe = opts
        .sssd_pipe
        .as_deref()
        .unwrap_or("/var/lib/sss/pipes/kcm");
    let sssd_pid = opts
        .sssd_pid
        .as_deref()
        .unwrap_or("/var/run/sssd.pid");

    let check1 = keytab::audit_keytab(keytab_path);
    let check2 = krb5_conf::audit_krb5_conf(krb5_conf_path);
    let check3 = sssd::audit_sssd(sssd_pipe, sssd_pid);
    let check4 = ticket::audit_ticket_lifetime(opts.ccache_path.as_deref());
    let check5 = tools::audit_host_tools();

    let mut checks = vec![check1, check2, check3, check4, check5];

    if opts.include_opsec {
        let check_opsec = opsec::audit_opsec_sensors(keytab_path, opts.ccache_path.as_deref());
        checks.push(check_opsec);
    }

    let passed = checks.iter().filter(|c| c.status == "PASS").count();
    let warnings = checks
        .iter()
        .filter(|c| c.status == "WARN" || c.status == "EXPIRED")
        .count();
    let failures = checks.iter().filter(|c| c.status == "FAIL").count();

    let status = if failures > 0 {
        "FAIL".to_string()
    } else if warnings > 0 {
        "WARN".to_string()
    } else {
        "PASS".to_string()
    };

    let elapsed = start.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;

    let timestamp = {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
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
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hours, mins, secs)
    };

    DoctorReport {
        status,
        timestamp,
        duration_ms,
        execution_time_ms: duration_ms,
        passed,
        warnings,
        failures,
        checks,
    }
}
