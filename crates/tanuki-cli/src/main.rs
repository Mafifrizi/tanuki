use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use tanuki::{
    candidates_to_json, entries_to_json, errors_to_json, find_error_resolution, ladder_to_json,
    parse_and_validate_jwt, parse_keytab_bytes, run_doctor, save_candidates, scan_for_ccache_blobs,
    validate_token_exchange, DoctorOptions, TokenExchangeParams, DECISION_LADDER, ERROR_DICTIONARY,
};

fn print_usage() {
    println!(
        r#"Tanuki CLI - Linux Active Directory Triage Engine

USAGE:
    tanuki <COMMAND> [OPTIONS]
    tanuki <KEYTAB_PATH> [--json]

COMMANDS:
    keytab [PATH]       Inspect binary keytab file (RFC 4120)
    kcm [OPTIONS]       Extract SSSD KCM credential cache streams
    triage [QUERY]      Lookup Kerberos/SSSD error codes and resolutions
    ladder              Display the 5-rung Tactical Decision Ladder
    doctor [OPTIONS]    Run proactive pre-flight diagnostic health checks
    token [TOKEN]       Validate workload identity JWT (RFC 8693 / NHI)
    nhi [SUBCOMMAND]    Non-Human Identity inspection and token exchange

OPTIONS:
    -f, --file <PATH>   Target database or keytab file
    -o, --out <DIR>     Output directory for extracted caches (default: ./extracted_ccache)
    -a, --audience <AUD> Expected audience for workload validation
    -i, --issuer <ISS>   Expected issuer for workload validation
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

    let mut global_json = false;
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
            cmd if explicit_command.is_none()
                && matches!(cmd, "keytab" | "kcm" | "triage" | "ladder" | "doctor" | "token" | "nhi") =>
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

    let data = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            emit_cli_error(
                &format!("Error reading keytab at '{}': {}", path, err),
                "MISSING_KEYTAB",
                "RESOURCE_MISSING",
                EXIT_RESOURCE_MISSING,
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

    println!("========================================================================");
    println!(" TANUKI KEYTAB TRIAGE REPORT");
    println!("========================================================================");
    for (idx, e) in entries.iter().enumerate() {
        println!("[{}] Principal : {}", idx + 1, e.principal);
        println!("    KVNO      : {}", e.vno);
        println!("    Enctype   : {} ({})", e.enctype_name, e.keytype);
        let preview = if e.key_hex.len() > 16 {
            &e.key_hex[..16]
        } else {
            &e.key_hex
        };
        println!("    Key (Hex) : {}... (length: {} bytes)", preview, e.key_len);
    }

    let aes_entries: Vec<_> = entries.iter().filter(|e| e.is_modern_aes()).collect();
    if let Some(sample) = aes_entries.first() {
        println!("\n[+] Recommended Non-Interactive TGT Acquisition (Modern AES):");
        println!("    $ kinit -k -t {} {}", path, sample.principal);
        println!("    $ export KRB5CCNAME=/tmp/krb5cc_$(id -u)");
    }
    println!("========================================================================");
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
                }
            }
            None => {
                if json_output {
                    println!("null");
                } else {
                    eprintln!("No matching error resolution found for '{}'", q);
                    eprintln!("Run 'tanuki triage' without arguments to see all known error codes.");
                }
                process::exit(1);
            }
        },
        None => {
            if json_output {
                let errors: Vec<_> = ERROR_DICTIONARY.iter().cloned().collect();
                println!("{}", errors_to_json(&errors));
            } else {
                println!("========================================================================");
                println!(" KERBEROS & SSSD ERROR RESOLUTION DICTIONARY");
                println!("========================================================================");
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
                println!("========================================================================");
            }
        }
    }
}

fn handle_ladder(json_output: bool) {
    if json_output {
        println!("{}", ladder_to_json());
        return;
    }

    println!("========================================================================");
    println!(" TANUKI 5-RUNG TACTICAL DECISION LADDER");
    println!("========================================================================");
    for rung in DECISION_LADDER {
        println!("[*] {}", rung.title);
        println!("    {}", rung.description);
        println!("    [BLUE TELEMETRY] {}\n", rung.telemetry.format_inline());
    }
    println!("Command Output Standard:");
    println!("    [TARGET] -> [PREREQUISITE] -> [TACTICAL CMD] -> [BLUE TELEMETRY] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]");
    println!("========================================================================");
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
                EXIT_USAGE_ERROR,
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
                println!("========================================================================");
                println!(" TANUKI NHI PASSIVE TOKEN SCANNER");
                println!("========================================================================");
                if found.is_empty() {
                    println!("No standard workload tokens discovered on local filesystem.");
                } else {
                    for p in &found {
                        println!("[FOUND] {}", p);
                    }
                }
                println!("========================================================================");
            }
        }
        other => {
            handle_token(Some(other.to_string()), file_path, audience, issuer, json_output);
        }
    }
}
