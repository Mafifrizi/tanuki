use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use tanuki::{
    candidates_to_json, entries_to_json, errors_to_json, find_error_resolution, generate_krb5_conf,
    ladder_to_json, parse_and_validate_jwt, parse_keytab_bytes, run_doctor, save_candidates,
    scan_for_ccache_blobs, validate_token_exchange, DoctorOptions, TokenExchangeParams,
    DECISION_LADDER, ERROR_DICTIONARY,
};

fn print_card_header(title: &str, subtitle: Option<&str>, width: usize) {
    let t_str = format!(" {} ", title);
    let title_chars = t_str.chars().count();
    let rem = if width > title_chars + 3 { width - title_chars - 3 } else { 2 };
    println!("┌──{}{}{}", t_str, "─".repeat(rem), "┐");
    if let Some(sub) = subtitle {
        let sub_chars = sub.chars().count();
        let pad = if width > sub_chars + 4 { width - sub_chars - 4 } else { 0 };
        println!("│ {}{} │", sub, " ".repeat(pad));
    }
    println!("└{}┘", "─".repeat(width - 2));
}

fn print_usage() {
    print_card_header(
        &format!("Tanuki CLI · Tactical Identity Operator (v{})", env!("CARGO_PKG_VERSION")),
        Some("Autonomous Non-Human Identity (NHI) & Hybrid Active Directory Engine"),
        72,
    );
    println!(
        r#"
USAGE:
    tanuki <COMMAND> [OPTIONS]
    tanuki <KEYTAB_PATH> [--json]

COMMANDS:
    doctor [OPTIONS]    Run proactive pre-flight diagnostic health checks (<5ms)
    keytab [PATH]       Inspect binary keytab file (RFC 4120)
    config [OPTIONS]    Generate unprivileged zero-DNS Kerberos config (RFC 4120)
    kcm [OPTIONS]       Extract SSSD KCM credential cache streams
    triage [QUERY]      Lookup Kerberos/SSSD error codes and resolutions
    ladder              Display the 5-rung Tactical Decision Ladder
    token [TOKEN]       Validate workload identity JWT (RFC 8693 / NHI)
    nhi [SUBCOMMAND]    Non-Human Identity inspection and token exchange
    skill [OPTIONS]     Display AI agent skill manifest and operational contract

OPTIONS:
    -f, --file <PATH>   Target database or keytab file
    -o, --out <PATH>    Output directory for extracted caches or config path
    -a, --audience <AUD> Expected audience for workload validation
    -i, --issuer <ISS>   Expected issuer for workload validation
    --realm <REALM>     Target Kerberos realm (mandates uppercase)
    --kdc <HOST_OR_IP>  KDC address or hostname (zero-DNS routing)
    --admin-server <HOST_OR_IP> Optional admin server for config
    --stdout            Print generated config directly to stdout
    --keytab <PATH>     Target keytab path for doctor
    --krb5-conf <PATH>  Target krb5.conf path for doctor
    --sssd-pipe <PATH>  Target SSSD KCM pipe socket path for doctor
    --sssd-pid <PATH>   Target SSSD pid path for doctor
    --ccache <PATH>     Target ccache path for doctor
    --json              Output structured JSON for agent and pipeline consumption
    -h, --help          Print help information
    -V, --version       Print version information"#
    );
}

const EXIT_SUCCESS: i32 = 0;
const EXIT_USAGE_ERROR: i32 = 1;
const EXIT_POLICY_STOP: i32 = 2;
const EXIT_RESOURCE_MISSING: i32 = 3;
const EXIT_PARSE_FAILURE: i32 = 4;

fn emit_cli_error(
    message: &str,
    reason_code: &str,
    category: &str,
    exit_code: i32,
    target: Option<&str>,
    details: Option<&str>,
    json_output: bool,
) -> ! {
    if json_output {
        let status = if exit_code == EXIT_POLICY_STOP { "REFUSED" } else { "ERROR" };
        let mut out = format!(
            "{{\n  \"status\": \"{}\",\n  \"reason_code\": \"{}\",\n  \"category\": \"{}\",\n  \"exit_code\": {},\n  \"message\": \"{}\"",
            status,
            reason_code,
            category,
            exit_code,
            message.replace('\\', "\\\\").replace('"', "\\\"")
        );
        if let Some(t) = target {
            out.push_str(&format!(",\n  \"target\": \"{}\"", t.replace('\\', "\\\\").replace('"', "\\\"")));
        }
        if let Some(d) = details {
            out.push_str(&format!(",\n  \"details\": \"{}\"", d.replace('\\', "\\\\").replace('"', "\\\"")));
        }
        out.push_str("\n}");
        println!("{}", out);
    } else {
        let prefix = match exit_code {
            EXIT_POLICY_STOP => "[POLICY STOP]",
            EXIT_RESOURCE_MISSING => "[RESOURCE MISSING]",
            EXIT_PARSE_FAILURE => "[PARSE FAILURE]",
            EXIT_USAGE_ERROR => "[USAGE ERROR]",
            _ => "[ERROR]",
        };
        if message.starts_with("Error:") || message.starts_with("Error ") {
            eprintln!("{} {}", prefix, message);
        } else {
            eprintln!("{} Error: {}", prefix, message);
        }
        if let Some(d) = details {
            eprintln!("  Details: {}", d);
        }
    }
    process::exit(exit_code);
}

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    if raw_args.is_empty() {
        print_usage();
        process::exit(EXIT_USAGE_ERROR);
    }

    let mut global_json = raw_args.iter().any(|a| a == "--json");
    let mut explicit_command: Option<String> = None;
    let mut positional_args: Vec<String> = Vec::new();
    let mut file_opt: Option<String> = None;
    let mut out_opt: Option<String> = None;
    let mut keytab_opt: Option<String> = None;
    let mut krb5_conf_opt: Option<String> = None;
    let mut sssd_pipe_opt: Option<String> = None;
    let mut sssd_pid_opt: Option<String> = None;
    let mut ccache_opt: Option<String> = None;
    let mut audience_opt: Option<String> = None;
    let mut issuer_opt: Option<String> = None;
    let mut realm_opt: Option<String> = None;
    let mut kdc_opt: Option<String> = None;
    let mut admin_server_opt: Option<String> = None;
    let mut stdout_opt = false;
    let mut grant_type_opt: Option<String> = None;
    let mut subject_token_opt: Option<String> = None;
    let mut subject_token_type_opt: Option<String> = None;
    let mut requested_token_type_opt: Option<String> = None;

    let mut i = 0;
    while i < raw_args.len() {
        match raw_args[i].as_str() {
            "-h" | "--help" => {
                print_usage();
                return;
            }
            "-V" | "--version" => {
                println!("tanuki-cli {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--json" => {
                global_json = true;
            }
            "-f" | "--file" => {
                if i + 1 < raw_args.len() {
                    file_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "-o" | "--out" => {
                if i + 1 < raw_args.len() {
                    out_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "-a" | "--audience" => {
                if i + 1 < raw_args.len() {
                    audience_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "-i" | "--issuer" => {
                if i + 1 < raw_args.len() {
                    issuer_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--grant-type" => {
                if i + 1 < raw_args.len() {
                    grant_type_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--subject-token" => {
                if i + 1 < raw_args.len() {
                    subject_token_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--subject-token-type" => {
                if i + 1 < raw_args.len() {
                    subject_token_type_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--requested-token-type" => {
                if i + 1 < raw_args.len() {
                    requested_token_type_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--keytab" => {
                if i + 1 < raw_args.len() {
                    keytab_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--krb5-conf" => {
                if i + 1 < raw_args.len() {
                    krb5_conf_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--sssd-pipe" => {
                if i + 1 < raw_args.len() {
                    sssd_pipe_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--sssd-pid" => {
                if i + 1 < raw_args.len() {
                    sssd_pid_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--ccache" => {
                if i + 1 < raw_args.len() {
                    ccache_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--realm" => {
                if i + 1 < raw_args.len() {
                    realm_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--kdc" => {
                if i + 1 < raw_args.len() {
                    kdc_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--admin-server" => {
                if i + 1 < raw_args.len() {
                    admin_server_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--stdout" => {
                stdout_opt = true;
            }
            cmd if explicit_command.is_none()
                && matches!(cmd, "keytab" | "kcm" | "triage" | "ladder" | "doctor" | "token" | "nhi" | "config" | "skill") =>
            {
                explicit_command = Some(cmd.to_string());
            }
            other if !other.starts_with('-') => {
                positional_args.push(other.to_string());
            }
            other => {
                emit_cli_error(
                    &format!("Unknown option: {}", other),
                    "UNKNOWN_OPTION",
                    "USAGE_ERROR",
                    EXIT_USAGE_ERROR,
                    Some(other),
                    None,
                    global_json,
                );
            }
        }
        i += 1;
    }

    let command = explicit_command.unwrap_or_else(|| {
        if file_opt.is_some() || !positional_args.is_empty() {
            "keytab".to_string()
        } else {
            "help".to_string()
        }
    });

    match command.as_str() {
        "keytab" => {
            let target_path = file_opt.or_else(|| positional_args.first().cloned());
            handle_keytab(target_path, global_json);
        }
        "kcm" => {
            let target_file = file_opt.or_else(|| positional_args.first().cloned());
            let out_dir = out_opt.unwrap_or_else(|| "./extracted_ccache".to_string());
            handle_kcm(target_file, &out_dir, global_json);
        }
        "triage" => {
            let query = positional_args.first().cloned();
            handle_triage(query.as_deref(), global_json);
        }
        "ladder" => {
            handle_ladder(global_json);
        }
        "doctor" => {
            let target_kt = keytab_opt.or(file_opt).or_else(|| positional_args.first().cloned());
            handle_doctor(
                global_json,
                target_kt,
                krb5_conf_opt,
                sssd_pipe_opt,
                sssd_pid_opt,
                ccache_opt,
            );
        }
        "config" => {
            let out_target = out_opt.or(file_opt);
            handle_config(
                realm_opt,
                keytab_opt,
                kdc_opt,
                admin_server_opt,
                out_target,
                stdout_opt,
                global_json,
            );
        }
        "token" => {
            let token_target = positional_args.first().cloned();
            handle_token(token_target, file_opt, audience_opt, issuer_opt, global_json);
        }
        "nhi" => {
            let subcmd = positional_args.first().map(|s| s.as_str()).unwrap_or("inspect");
            let remaining = if positional_args.len() > 1 {
                &positional_args[1..]
            } else {
                &[]
            };
            handle_nhi(
                subcmd,
                remaining,
                file_opt,
                audience_opt,
                issuer_opt,
                grant_type_opt,
                subject_token_opt,
                subject_token_type_opt,
                requested_token_type_opt,
                global_json,
            );
        }
        "skill" => {
            handle_skill(global_json);
        }
        "help" => {
            print_usage();
        }
        _ => {
            emit_cli_error(
                &format!("Unknown command: {}", command),
                "UNKNOWN_COMMAND",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                Some(&command),
                None,
                global_json,
            );
        }
    }
}

fn handle_keytab(file_path: Option<String>, json_output: bool) {
    let path = match file_path {
        Some(p) => p,
        None => {
            emit_cli_error(
                "Error: Keytab path required. Example: tanuki keytab /etc/krb5.keytab",
                "MISSING_ARGUMENT",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                None,
                None,
                json_output,
            );
        }
    };

    if !Path::new(&path).exists() {
        emit_cli_error(
            &format!("Error reading keytab at '{}': No such file or directory", path),
            "MISSING_KEYTAB",
            "RESOURCE_MISSING",
            EXIT_RESOURCE_MISSING,
            Some(&path),
            None,
            json_output,
        );
    }

    let data = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            emit_cli_error(
                &format!("Error reading keytab at '{}': {}", path, err),
                "CORRUPT_KEYTAB",
                "PARSE_FAILURE",
                EXIT_PARSE_FAILURE,
                Some(&path),
                Some(&err.to_string()),
                json_output,
            );
        }
    };

    let entries = match parse_keytab_bytes(&data) {
        Ok(list) => list,
        Err(err) => {
            emit_cli_error(
                &format!("Error parsing keytab: {}", err),
                "CORRUPT_KEYTAB",
                "PARSE_FAILURE",
                EXIT_PARSE_FAILURE,
                Some(&path),
                Some(&err.to_string()),
                json_output,
            );
        }
    };

    if json_output {
        println!("{}", entries_to_json(&entries));
        return;
    }

    print_card_header(
        "TANUKI KEYTAB TRIAGE REPORT",
        Some(&format!("File: {} · RFC 4120 Binary Structure", path)),
        72,
    );
    for (idx, e) in entries.iter().enumerate() {
        println!("[{}] Principal : {}", idx + 1, e.principal);
        println!("    ├─ KVNO      : {}", e.vno);
        println!("    ├─ Enctype   : {} ({})", e.enctype_name, e.keytype);
        let preview = if e.key_hex.len() > 16 {
            &e.key_hex[..16]
        } else {
            &e.key_hex
        };
        println!("    ╰─ Key (Hex) : {}... (length: {} bytes)", preview, e.key_len);
    }

    let aes_entries: Vec<_> = entries.iter().filter(|e| e.is_modern_aes()).collect();
    if let Some(sample) = aes_entries.first() {
        let env_krb5_conf = std::env::var("KRB5_CONFIG").ok();
        let prefix = match &env_krb5_conf {
            Some(p) => format!("KRB5_CONFIG={} ", p),
            None => String::new(),
        };
        println!("\n[+] Recommended Non-Interactive TGT Acquisition (Modern AES):");
        println!("    $ {}kinit -k -t {} {}", prefix, path, sample.principal);
        println!("    $ export KRB5CCNAME=/tmp/krb5cc_$(id -u)");

        if tanuki::doctor::tools::has_binary_on_path("kinit").is_none() {
            println!("\n[!] Host Tooling Advisory:");
            println!("    'kinit' utility not found on PATH.");
            println!("    Install: sudo apt install krb5-user (Debian/Kali) or sudo dnf install krb5-workstation (RHEL)");
            println!("    Unprivileged: Generate local config via 'tanuki config' and use portable client.");
        }
    }
    println!("{}", "─".repeat(72));
}

fn handle_config(
    realm_opt: Option<String>,
    keytab_opt: Option<String>,
    kdc_opt: Option<String>,
    admin_server_opt: Option<String>,
    out_path: Option<String>,
    stdout_mode: bool,
    json_output: bool,
) {
    let realm = match realm_opt {
        Some(r) if !r.trim().is_empty() => r.trim().to_uppercase(),
        _ => match keytab_opt {
            Some(kt_path) => {
                if !Path::new(&kt_path).exists() {
                    emit_cli_error(
                        &format!("Error reading keytab at '{}': No such file or directory", kt_path),
                        "MISSING_KEYTAB",
                        "RESOURCE_MISSING",
                        EXIT_RESOURCE_MISSING,
                        Some(&kt_path),
                        None,
                        json_output,
                    );
                }
                let data = match fs::read(&kt_path) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        emit_cli_error(
                            &format!("Error reading keytab at '{}': {}", kt_path, err),
                            "CORRUPT_KEYTAB",
                            "PARSE_FAILURE",
                            EXIT_PARSE_FAILURE,
                            Some(&kt_path),
                            Some(&err.to_string()),
                            json_output,
                        );
                    }
                };
                if data.is_empty() {
                    emit_cli_error(
                        &format!("Keytab file is empty: '{}'", kt_path),
                        "EMPTY_KEYTAB",
                        "PARSE_FAILURE",
                        EXIT_PARSE_FAILURE,
                        Some(&kt_path),
                        None,
                        json_output,
                    );
                }
                let entries = match parse_keytab_bytes(&data) {
                    Ok(list) => list,
                    Err(err) => {
                        emit_cli_error(
                            &format!("Error parsing keytab: {}", err),
                            "CORRUPT_KEYTAB",
                            "PARSE_FAILURE",
                            EXIT_PARSE_FAILURE,
                            Some(&kt_path),
                            Some(&err.to_string()),
                            json_output,
                        );
                    }
                };
                if entries.is_empty() {
                    emit_cli_error(
                        &format!("Keytab contains no entries: '{}'", kt_path),
                        "EMPTY_KEYTAB",
                        "PARSE_FAILURE",
                        EXIT_PARSE_FAILURE,
                        Some(&kt_path),
                        None,
                        json_output,
                    );
                }
                let mut found_realm: Option<String> = None;
                for entry in entries {
                    let trimmed = entry.realm.trim();
                    if !trimmed.is_empty() {
                        found_realm = Some(trimmed.to_uppercase());
                        break;
                    }
                }
                match found_realm {
                    Some(r) => r,
                    None => {
                        emit_cli_error(
                            &format!("No non-empty realm found in keytab: '{}'", kt_path),
                            "EMPTY_KEYTAB",
                            "PARSE_FAILURE",
                            EXIT_PARSE_FAILURE,
                            Some(&kt_path),
                            None,
                            json_output,
                        );
                    }
                }
            }
            None => {
                emit_cli_error(
                    "Error: Realm required for configuration generation. Example: tanuki config --realm CORP.LOCAL --kdc 192.168.56.106",
                    "MISSING_ARGUMENT",
                    "USAGE_ERROR",
                    EXIT_USAGE_ERROR,
                    None,
                    None,
                    json_output,
                );
            }
        },
    };
    let kdc = match kdc_opt {
        Some(k) => k,
        None => {
            emit_cli_error(
                "Error: KDC address or hostname required. Example: tanuki config --realm CORP.LOCAL --kdc 192.168.56.106",
                "MISSING_ARGUMENT",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                None,
                None,
                json_output,
            );
        }
    };

    let content = match generate_krb5_conf(&realm, &kdc, admin_server_opt.as_deref()) {
        Ok(c) => c,
        Err(err) => {
            emit_cli_error(
                &format!("Error generating config: {}", err),
                "CONFIG_ERROR",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                None,
                Some(&err),
                json_output,
            );
        }
    };

    if stdout_mode && !json_output {
        print!("{}", content);
        return;
    }

    let target_file = out_path.unwrap_or_else(|| "./krb5.conf".to_string());
    let target_path = PathBuf::from(&target_file);
    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = fs::create_dir_all(parent);
        }
    }

    if let Err(err) = fs::write(&target_file, &content) {
        emit_cli_error(
            &format!("Failed to write configuration file: {}", err),
            "WRITE_ERROR",
            "PARSE_FAILURE",
            EXIT_PARSE_FAILURE,
            Some(&target_file),
            Some(&err.to_string()),
            json_output,
        );
    }

    let abs_path = target_path
        .canonicalize()
        .unwrap_or_else(|_| match env::current_dir() {
            Ok(cwd) => cwd.join(&target_path),
            Err(_) => target_path.clone(),
        });
    let abs_str = abs_path.to_string_lossy().to_string();

    let export_cmd = format!("export KRB5_CONFIG={}", abs_str);
    let clean_realm = realm.trim().to_uppercase();
    let target_admin = admin_server_opt.as_deref().unwrap_or(kdc.trim());

    if json_output {
        println!(
            "{{\n  \"status\": \"SUCCESS\",\n  \"realm\": \"{}\",\n  \"kdc\": \"{}\",\n  \"admin_server\": \"{}\",\n  \"config_path\": \"{}\",\n  \"export_command\": \"{}\",\n  \"content\": \"{}\"\n}}",
            clean_realm,
            kdc.trim(),
            target_admin,
            abs_str.replace('\\', "\\\\").replace('"', "\\\""),
            export_cmd.replace('\\', "\\\\").replace('"', "\\\""),
            tanuki::escape_json(&content)
        );
        return;
    }

    print_card_header(
        "TANUKI UNPRIVILEGED KERBEROS CONFIG GENERATOR",
        Some("Zero-DNS Direct Routing · RFC 4120 Compliant"),
        72,
    );
    println!("[+] Output File    : {}", abs_str);
    println!("    ├─ Target Realm   : {} (RFC 4120 uppercase convention)", clean_realm);
    println!("    ├─ Target KDC     : {} (zero-DNS direct routing)", kdc.trim());
    println!("    ╰─ Admin Server   : {}", target_admin);
    println!("\n[+] To activate in your current session (unprivileged / no root required):");
    println!("    $ {}", export_cmd);
    println!("    $ kinit -k -t <keytab> <principal>");
    println!("{}", "─".repeat(72));
}

fn handle_kcm(file_path: Option<String>, out_dir: &str, json_output: bool) {
    let out_path = PathBuf::from(out_dir);

    if let Some(path) = file_path {
        let data = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => {
                emit_cli_error(
                    &format!("Error reading database '{}': {}", path, err),
                    "MISSING_RESOURCE",
                    "RESOURCE_MISSING",
                    EXIT_RESOURCE_MISSING,
                    Some(&path),
                    Some(&err.to_string()),
                    json_output,
                );
            }
        };

        let candidates = scan_for_ccache_blobs(&data);
        if json_output {
            println!("{}", candidates_to_json(&candidates));
            return;
        }

        println!("[*] Found {} candidate ccache streams in {}", candidates.len(), path);
        match save_candidates(&candidates, &out_path, "ticket") {
            Ok(saved) => {
                for file in saved {
                    println!("    -> Saved {}", file.display());
                }
            }
            Err(err) => {
                eprintln!("Failed to save extracted tickets: {}", err);
            }
        }
    } else {
        scan_local_stores(&out_path, json_output);
    }
}

fn scan_local_stores(out_path: &Path, json_output: bool) {
    let candidate_locations = [
        "/var/lib/sss/secrets/secrets.ldb",
        "/var/lib/sss/db/cache_default.ldb",
    ];

    let mut all_candidates = Vec::new();
    let mut discovered_files = Vec::new();

    for loc in &candidate_locations {
        let p = Path::new(loc);
        if p.exists() {
            if let Ok(data) = fs::read(p) {
                let found = scan_for_ccache_blobs(&data);
                if !found.is_empty() {
                    let prefix = p.file_stem().and_then(|s| s.to_str()).unwrap_or("recovered");
                    if let Ok(saved) = save_candidates(&found, out_path, prefix) {
                        discovered_files.extend(saved);
                    }
                    all_candidates.extend(found);
                }
            }
        }
    }

    if json_output {
        println!("{}", candidates_to_json(&all_candidates));
        return;
    }

    println!("[*] Phase 1: Scanning SSSD KCM database stores...");
    if discovered_files.is_empty() {
        println!("  [-] No accessible or unencrypted KCM database stores found.");
    } else {
        for f in &discovered_files {
            println!("  [+] Recovered KCM ticket blob -> {}", f.display());
        }
    }

    println!("\n[*] Phase 2: Scanning traditional file-based credential caches...");
    let tmp_dir = Path::new("/tmp");
    let mut file_ccaches = Vec::new();
    if let Ok(entries) = fs::read_dir(tmp_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("krb5cc_") {
                    println!("  [+] Discovered active file ccache: {}", entry.path().display());
                    file_ccaches.push(entry.path());
                }
            }
        }
    }

    if discovered_files.is_empty() && file_ccaches.is_empty() {
        println!("  [-] No unencrypted ccache blobs discovered in evaluated paths.");
    } else if !discovered_files.is_empty() {
        println!(
            "\n[+] Set environment to utilize recovered ticket:\n    $ export KRB5CCNAME={}/<ticket>.ccache",
            out_path.display()
        );
    }
}

fn handle_triage(query: Option<&str>, json_output: bool) {
    match query {
        Some(q) => match find_error_resolution(q) {
            Some(res) => {
                if json_output {
                    println!("{}", res.to_json());
                } else {
                    let sub = res.event_id.map(|id| format!("Event ID: {} · Root Cause Diagnostic", id));
                    print_card_header(
                        &format!("TANUKI PROTOCOL TRIAGE: {}", res.code),
                        sub.as_deref().or(Some("RFC / SSSD Error Vector Diagnostic")),
                        72,
                    );
                    println!("Found matching error: {}", res.code);
                    if let Some(id) = res.event_id {
                        println!("Event ID: {}", id);
                    }
                    println!("Root Cause: {}", res.root_cause);
                    println!("Resolution:\n{}", res.resolution);
                    println!();
                    println!("[TACTICAL CMD]");
                    println!("    $ {}", res.tactical_cmd);
                    println!();
                    println!("{}", res.telemetry.format_terminal());
                    println!("{}", "─".repeat(72));
                }
            }
            None => {
                emit_cli_error(
                    &format!("No matching error resolution found for '{}'", q),
                    "UNKNOWN_ERROR_CODE",
                    "PROTOCOL_ERROR",
                    EXIT_RESOURCE_MISSING,
                    Some(q.as_str()),
                    Some("Run 'tanuki triage' without arguments to see all known error codes."),
                    json_output,
                );
            }
        },
        None => {
            if json_output {
                let errors: Vec<_> = ERROR_DICTIONARY.iter().cloned().collect();
                println!("{}", errors_to_json(&errors));
            } else {
                print_card_header(
                    "KERBEROS & SSSD ERROR RESOLUTION DICTIONARY",
                    Some("10 Pre-compiled Protocol Vectors · Dual-Use Detection Telemetry"),
                    72,
                );
                for item in ERROR_DICTIONARY {
                    let event = item
                        .event_id
                        .map(|id| format!(" (Event {})", id))
                        .unwrap_or_default();
                    println!("\nError Code: {}{}", item.code, event);
                    println!("Root Cause: {}", item.root_cause);
                    println!("Tactical Resolution:\n{}", item.resolution);
                    println!("[TACTICAL CMD]:\n    $ {}", item.tactical_cmd);
                    println!("[BLUE TELEMETRY]:\n    {}", item.telemetry.format_inline());
                }
                println!("{}", "─".repeat(72));
            }
        }
    }
}

fn handle_ladder(json_output: bool) {
    if json_output {
        println!("{}", ladder_to_json());
        return;
    }

    print_card_header(
        "TANUKI 5-RUNG TACTICAL DECISION LADDER",
        Some("Disciplined Agent SOP · Zero-Noise OPSEC Standard"),
        72,
    );
    for rung in DECISION_LADDER {
        println!("[*] {}", rung.title);
        println!("    {}", rung.description);
        println!("    [BLUE TELEMETRY] {}\n", rung.telemetry.format_inline());
    }
    println!("Command Output Standard:");
    println!("    [TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]");
    println!("{}", "─".repeat(72));
}

fn handle_doctor(
    json_output: bool,
    keytab_path: Option<String>,
    krb5_conf: Option<String>,
    sssd_pipe: Option<String>,
    sssd_pid: Option<String>,
    ccache_path: Option<String>,
) {
    let opts = DoctorOptions {
        keytab_path: keytab_path.or_else(|| Some("/etc/krb5.keytab".to_string())),
        krb5_conf_path: krb5_conf.or_else(|| Some("/etc/krb5.conf".to_string())),
        sssd_pipe: sssd_pipe.or_else(|| Some("/var/lib/sss/pipes/kcm".to_string())),
        sssd_pid: sssd_pid.or_else(|| Some("/var/run/sssd.pid".to_string())),
        ccache_path,
    };

    let report = run_doctor(&opts);
    if json_output {
        println!("{}", report.to_json());
    } else {
        println!("{}", report.format_checklist());
    }

    if report.status == "FAIL" {
        let has_policy_stop = report.checks.iter().any(|c| {
            c.status == "FAIL"
                && (!c.is_secure_permissions.unwrap_or(true) || c.has_weak_enctypes.unwrap_or(false))
        });
        if has_policy_stop {
            process::exit(EXIT_POLICY_STOP);
        }

        let has_missing_resource = report.checks.iter().any(|c| {
            (c.status == "FAIL" || c.status == "N_A")
                && !c.exists.unwrap_or(true)
                && (c.name == "keytab_permissions" || c.name == "sssd_subsystem")
        });
        if has_missing_resource {
            process::exit(EXIT_RESOURCE_MISSING);
        }

        process::exit(EXIT_POLICY_STOP);
    }
}

fn handle_token(
    token_arg: Option<String>,
    file_path: Option<String>,
    audience: Option<String>,
    _issuer: Option<String>,
    json_output: bool,
) {
    let raw_token = if let Some(path) = file_path {
        match fs::read_to_string(&path) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                emit_cli_error(
                    &format!("Error: Token file not found: {}", path),
                    "MISSING_RESOURCE",
                    "RESOURCE_MISSING",
                    EXIT_USAGE_ERROR,
                    Some(&path),
                    Some(&e.to_string()),
                    json_output,
                );
            }
        }
    } else if let Some(arg) = token_arg {
        if arg.is_empty() {
            emit_cli_error(
                "Error: Token string cannot be empty",
                "MISSING_ARGUMENT",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                None,
                None,
                json_output,
            );
        }
        if Path::new(&arg).is_file() {
            fs::read_to_string(&arg)
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| arg)
        } else {
            arg
        }
    } else {
        use std::io::Read;
        let mut buf = String::new();
        if std::io::stdin().read_to_string(&mut buf).is_ok() && !buf.trim().is_empty() {
            buf.trim().to_string()
        } else {
            emit_cli_error(
                "Error: No token provided. Pass as argument, -f/--file, or via stdin.",
                "MISSING_ARGUMENT",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                None,
                None,
                json_output,
            );
        }
    };

    if raw_token.is_empty() {
        emit_cli_error(
            "Error: Token string cannot be empty",
            "MISSING_ARGUMENT",
            "USAGE_ERROR",
            EXIT_USAGE_ERROR,
            None,
            None,
            json_output,
        );
    }

    match parse_and_validate_jwt(&raw_token, audience.as_deref()) {
        Ok(report) => {
            if json_output {
                println!("{}", report.to_json());
            } else {
                println!("{}", report.format_terminal());
            }
        }
        Err(e) => {
            emit_cli_error(
                &format!("Error parsing token: {}", e),
                "CORRUPT_DATA",
                "PARSE_FAILURE",
                EXIT_PARSE_FAILURE,
                None,
                Some(&e.to_string()),
                json_output,
            );
        }
    }
}

fn handle_nhi(
    subcmd: &str,
    positional_args: &[String],
    file_path: Option<String>,
    audience: Option<String>,
    issuer: Option<String>,
    grant_type: Option<String>,
    subject_token: Option<String>,
    subject_token_type: Option<String>,
    requested_token_type: Option<String>,
    json_output: bool,
) {
    match subcmd {
        "inspect" => {
            let token_arg = positional_args.first().cloned();
            handle_token(token_arg, file_path, audience, issuer, json_output);
        }
        "exchange" => {
            let sub_tok = if let Some(st) = subject_token {
                Some(st)
            } else if let Some(fp) = &file_path {
                fs::read_to_string(fp).ok().map(|s| s.trim().to_string())
            } else {
                positional_args.first().cloned()
            };

            let params = TokenExchangeParams {
                grant_type,
                subject_token: sub_tok,
                subject_token_type,
                requested_token_type,
                audience,
                resource: None,
                scope: None,
            };

            let report = validate_token_exchange(&params);
            if json_output {
                println!("{}", report.to_json());
            } else {
                println!("{}", report.format_terminal());
            }
            if !report.valid {
                process::exit(EXIT_USAGE_ERROR);
            }
        }
        "scan" => {
            let known_paths = [
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
                "/run/secrets/kubernetes.io/serviceaccount/token",
            ];
            let mut found = Vec::new();
            for p in &known_paths {
                if Path::new(p).is_file() {
                    found.push(p.to_string());
                }
            }
            if json_output {
                let items: Vec<String> = found.iter().map(|p| format!("\"{}\"", p)).collect();
                println!("{{\n  \"discovered_tokens\": [{}]\n}}", items.join(", "));
            } else {
                print_card_header("TANUKI NHI PASSIVE TOKEN SCANNER", Some("Filesystem Workload Identity Probes"), 72);
                if found.is_empty() {
                    println!("No standard workload tokens discovered on local filesystem.");
                } else {
                    for p in &found {
                        println!("[FOUND] {}", p);
                    }
                }
                println!("{}", "─".repeat(72));
            }
        }
        other => {
            handle_token(Some(other.to_string()), file_path, audience, issuer, json_output);
        }
    }
}

fn handle_skill(json_output: bool) {
    if json_output {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str("  \"name\": \"tanuki\",\n");
        out.push_str(&format!("  \"version\": \"{}\",\n", env!("CARGO_PKG_VERSION")));
        out.push_str("  \"description\": \"Autonomous Non-Human Identity (NHI) and Hybrid Active Directory Operator for Linux.\",\n");
        out.push_str("  \"author\": \"Tanuki Open Source Initiative\",\n");
        out.push_str("  \"lineage\": {\n");
        out.push_str("    \"pioneer_unix_tradecraft\": \"Tim Brown (@timb-machine), creator of Linikatz\",\n");
        out.push_str("    \"pioneer_agentic_ladder\": \"Dietrich Gebert (@dietrichayala), creator of Ponytail\"\n");
        out.push_str("  },\n");
        out.push_str("  \"triggers\": [\n");
        out.push_str("    \"active directory\",\n    \"kerberos\",\n    \"keytab\",\n    \"sssd\",\n    \"kcm\",\n    \"certipy\",\n    \"ad cs\",\n    \"shadow credentials\",\n    \"rbcd\",\n    \"workload identity\",\n    \"tanuki doctor\",\n    \"pre-flight\",\n    \"telemetry\",\n    \"auditd\",\n    \"rfc 8693\",\n    \"token exchange\"\n");
        out.push_str("  ],\n");
        out.push_str("  \"output_standard\": \"[TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]\",\n");
        out.push_str(&format!("  \"ladder\": {}\n", ladder_to_json()));
        out.push_str("}");
        println!("{}", out);
        return;
    }

    print_card_header(
        "TANUKI AI AGENT SKILL MANIFEST",
        Some(&format!("v{} · Dual-Engine Non-Human Identity Operator", env!("CARGO_PKG_VERSION"))),
        72,
    );
    println!("[*] Intellectual Lineage & Pioneers:");
    println!("    ├─ Tim Brown (@timb-machine)        : Linikatz & UNIX Active Directory Assessment");
    println!("    ╰─ Dietrich Gebert (@dietrichayala) : Ponytail Decision Ladder Methodology\n");
    println!("[*] Tactical Activation Triggers:");
    println!("    active directory, kerberos, keytab, sssd, kcm, certipy, ad cs, shadow credentials, ...\n");
    println!("[*] 5-Rung Operator Tactical Decision Ladder:");
    for rung in DECISION_LADDER {
        println!("    [{}] {}", rung.rung, rung.title);
    }
    println!();
    println!("[*] Deterministic Command Output Standard:");
    println!("    [TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]");
    println!("{}", "─".repeat(72));
}
