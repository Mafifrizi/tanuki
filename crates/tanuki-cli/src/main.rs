use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;
use tanuki::{
    candidates_to_json, entries_to_json, errors_to_json, find_error_resolution,
    format_pac_report_terminal, generate_krb5_conf, ladder_to_json, pac_report_to_json,
    parse_and_validate_jwt, parse_keytab_bytes, parse_pac_source, query_active_directory_ldap,
    run_doctor, run_fix, run_purge, save_candidates, scan_adcs_source, scan_for_ccache_blobs,
    validate_token_exchange, DoctorOptions, TokenExchangeParams, DECISION_LADDER, ERROR_DICTIONARY,
};

const TANUKI_BANNER: &str = r#" _____     _     _   _   _   _   _  __   _____ 
|_   _|   / \   | \ | | | | | | | |/ /  |_   _|
  | |    / _ \  |  \| | | | | | | ' /     | |  
  | |   / ___ \ | |\  | | |_| | | . \     | |  
  |_|   /_/   \ |_| \_|  \___/  |_|\_\   |___| "#;

fn print_card_header(title: &str, subtitle: Option<&str>, _width: usize) {
    println!("[{}]", title);
    if let Some(sub) = subtitle {
        println!(" {}", sub);
    }
}

fn print_usage() {
    println!("{}", TANUKI_BANNER);
    println!();
    print_card_header(
        &format!("Tanuki CLI · Tactical Identity Operator (v{})", env!("CARGO_PKG_VERSION")),
        Some("Autonomous Non-Human Identity (NHI) & Hybrid Active Directory Engine"),
        72,
    );
    println!();
    println!(
        r#"USAGE:
    tanuki <COMMAND> [OPTIONS]
    tanuki <KEYTAB_PATH> [--json]

COMMANDS:
    doctor [OPTIONS]    Run proactive pre-flight diagnostic health checks (<5ms)
    fix [OPTIONS]       Idempotent closed-loop self-healing remediation
    purge [OPTIONS]     Cryptographic zero-trace forensic purge (NIST SP 800-88)
    pac <FILE|HEX>      Decode and audit MS-PAC authorization data
    adcs <FILE|SOURCE>  Scan Active Directory Certificate Templates (ESC1-ESC11)
    ldap [OPTIONS]      Unprivileged Active Directory LDAP query engine
    keytab [PATH]       Inspect binary keytab file (RFC 4120)
    config [OPTIONS]    Generate unprivileged zero-DNS Kerberos config (RFC 4120)
    auth [OPTIONS]      Acquire TGT using keytab via host kinit
    kcm [OPTIONS]       Extract SSSD KCM credential cache streams
    triage [QUERY]      Lookup Kerberos/SSSD error codes and resolutions
    ladder              Display the 5-rung Tactical Decision Ladder
    token [TOKEN]       Validate workload identity JWT (RFC 8693 / NHI)
    nhi [SUBCOMMAND]    Non-Human Identity inspection and token exchange
    skill [OPTIONS]     Display AI agent skill manifest and operational contract

OPTIONS:
    -i, --interactive   Launch fast, interactive TUI wizard menu
    -f, --file <PATH>   Target database, keytab, template or token file
    -o, --out <PATH>    Output directory for extracted caches or config path
    -p, --principal <P> Kerberos principal for authentication
    -a, --audience <AUD> Expected audience for workload validation
    --issuer <ISS>      Expected issuer for workload validation
    --realm <REALM>     Target Kerberos realm (mandates uppercase)
    --kdc <HOST_OR_IP>  KDC address or hostname (supports multiple or comma-separated)
    --admin-server <HOST_OR_IP> Optional admin server for config
    --clock-skew <SECS> Clock skew tolerance in seconds (unprivileged hypervisors)
    --enforce-aes       Strictly enforce AES-128/256 and reject legacy RC4
    --stdout            Print generated config directly to stdout
    --keytab <PATH>     Target keytab path for doctor/auth/config/fix
    --krb5-conf <PATH>  Target krb5.conf path for doctor/fix
    --sssd-pipe <PATH>  Target SSSD KCM pipe socket path for doctor
    --sssd-pid <PATH>   Target SSSD pid path for doctor
    --ccache <PATH>     Target ccache path for doctor/auth/fix
    --opsec             Include live host OPSEC sensor probe in pre-flight doctor
    --dry-run           Simulate remediation without applying changes (for tanuki fix)
    --all               Purge all discovered ticket caches and temp configs
    --host <HOST_OR_IP> Target Active Directory domain controller for LDAP
    --query <TYPE>      LDAP query category (spn, rbcd, shadow, unconstrained, all)
    --base-dn <DN>      Base DN for directory query (e.g. DC=corp,DC=local)
    --port <PORT>       Target LDAP port (default: 389)
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

fn read_line_prompt(prompt: &str) -> Option<String> {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    let mut line = String::new();
    match io::stdin().read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(line.trim().to_string()),
        Err(_) => None,
    }
}

fn run_tui_wizard() {
    loop {
        println!("{}", TANUKI_BANNER);
        println!();
        print_card_header(
            "TANUKI INTERACTIVE WIZARD",
            Some("Pillar 10 · Tactical Identity TUI Navigator"),
            72,
        );
        println!("  [1]  Doctor   : Run proactive identity health checks (<5ms)");
        println!("  [2]  Fix      : Idempotent self-healing remediation");
        println!("  [3]  Keytab   : Inspect Kerberos keytab binary entries");
        println!("  [4]  Auth     : Acquire Kerberos TGT ticket cache via kinit");
        println!("  [5]  PAC      : Decode MS-PAC binary structures & privileges");
        println!("  [6]  LDAP     : Query Active Directory via unprivileged SASL GSSAPI");
        println!("  [7]  AD CS    : Passive certificate & template scanner (ESC1-ESC11)");
        println!("  [8]  NHI      : Workload identity inspection & token exchange");
        println!("  [9]  KCM      : Extract SSSD KCM credential cache streams");
        println!("  [10] Triage   : Lookup Kerberos protocol error resolutions");
        println!("  [11] Ladder   : Display 5-rung Tactical Decision Ladder");
        println!("  [12] Purge    : Cryptographic zero-trace artifact sanitization");
        println!("  [13] Skill    : Display AI agent skill manifest");
        println!("  [0]  Exit");
        println!();

        let choice = match read_line_prompt("Select an option [0-13]: ") {
            Some(c) => c,
            None => {
                println!("\nExiting Tanuki.");
                process::exit(0);
            }
        };

        match choice.as_str() {
            "0" | "exit" | "quit" | "q" => {
                println!("Exiting Tanuki.");
                process::exit(0);
            }
            "1" => {
                handle_doctor(false, None, None, None, None, None, false);
            }
            "2" => {
                handle_fix(None, None, None, None, None, false, 300, false);
            }
            "3" => {
                let kt = match read_line_prompt("Keytab path [/etc/krb5.keytab]: ") {
                    Some(s) if !s.is_empty() => s,
                    _ => "/etc/krb5.keytab".to_string(),
                };
                handle_keytab(Some(kt), false);
            }
            "4" => {
                let kt = match read_line_prompt("Keytab path [/etc/krb5.keytab]: ") {
                    Some(s) if !s.is_empty() => s,
                    _ => "/etc/krb5.keytab".to_string(),
                };
                let princ = read_line_prompt("Principal (optional): ").filter(|s| !s.is_empty());
                handle_auth(Some(kt), princ, None, false, None);
            }
            "5" => {
                let pac_src = read_line_prompt("Target PAC file path or hex: ").unwrap_or_default();
                handle_pac(Some(pac_src), false);
            }
            "6" => {
                let host = read_line_prompt("Target DC IP/Host: ").unwrap_or_default();
                let q = match read_line_prompt("Query type (spn/rbcd/shadow/unconstrained/all) [all]: ") {
                    Some(s) if !s.is_empty() => s,
                    _ => "all".to_string(),
                };
                handle_ldap(Some(host), &q, "DC=corp,DC=local", 389, false);
            }
            "7" => {
                let src = read_line_prompt("Templates JSON or Certificate path: ").unwrap_or_default();
                handle_adcs(Some(src), false);
            }
            "8" => {
                let tok = read_line_prompt("Enter JWT token or path: ").unwrap_or_default();
                handle_token(Some(tok), None, None, None, false);
            }
            "9" => {
                let f = read_line_prompt("KCM database path (optional): ").filter(|s| !s.is_empty());
                handle_kcm(f, "./extracted_ccache", false);
            }
            "10" => {
                let q = read_line_prompt("Error code or query (blank for all): ").filter(|s| !s.is_empty());
                handle_triage(q.as_deref(), false);
            }
            "11" => {
                handle_ladder(false);
            }
            "12" => {
                let conf = read_line_prompt("Confirm purge all cached credentials and configs? (y/N): ")
                    .unwrap_or_default()
                    .to_lowercase();
                if conf == "y" {
                    handle_purge(None, true, false);
                } else {
                    println!("Purge aborted.");
                }
            }
            "13" => {
                handle_skill(false);
            }
            _ => {
                println!("Invalid option.");
            }
        }

        let _ = read_line_prompt("\nPress Enter to return to menu...");
    }
}

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    if raw_args.is_empty() {
        if io::stdin().is_terminal() && io::stdout().is_terminal() {
            run_tui_wizard();
            return;
        }
        print_usage();
        process::exit(EXIT_USAGE_ERROR);
    }

    let known_subcommands = [
        "keytab", "kcm", "triage", "ladder", "doctor", "token", "nhi", "config", "skill", "auth",
        "pac", "fix", "purge", "adcs", "ldap",
    ];

    if raw_args.len() == 1 && (raw_args[0] == "-i" || raw_args[0] == "--interactive") {
        run_tui_wizard();
        return;
    }

    if raw_args.iter().any(|a| a == "--interactive")
        && !raw_args.iter().any(|a| known_subcommands.contains(&a.as_str()))
    {
        run_tui_wizard();
        return;
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
    let mut principal_opt: Option<String> = None;
    let mut clock_skew_opt: Option<u32> = None;
    let mut enforce_aes_opt = false;
    let mut opsec_opt = false;
    let mut dry_run_opt = false;
    let mut purge_all_opt = false;
    let mut host_opt: Option<String> = None;
    let mut query_opt: Option<String> = None;
    let mut base_dn_opt: Option<String> = None;
    let mut port_opt: Option<u16> = None;

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
            "-p" | "--principal" => {
                if i + 1 < raw_args.len() {
                    principal_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "-a" | "--audience" => {
                if i + 1 < raw_args.len() {
                    audience_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--interactive" => {
                if explicit_command.is_none() {
                    run_tui_wizard();
                    return;
                }
            }
            "-i" | "--issuer" => {
                if i + 1 < raw_args.len() && !raw_args[i + 1].starts_with('-') {
                    issuer_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else if explicit_command.is_none()
                    && !raw_args.iter().any(|a| known_subcommands.contains(&a.as_str()))
                {
                    run_tui_wizard();
                    return;
                } else {
                    emit_cli_error(
                        "Option requires an argument: -i/--issuer",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
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
                    let k = raw_args[i + 1].clone();
                    if let Some(ref mut existing) = kdc_opt {
                        existing.push(',');
                        existing.push_str(&k);
                    } else {
                        kdc_opt = Some(k);
                    }
                    i += 1;
                }
            }
            "--admin-server" => {
                if i + 1 < raw_args.len() {
                    admin_server_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--clock-skew" | "--clockskew" => {
                if i + 1 < raw_args.len() {
                    match raw_args[i + 1].parse::<u32>() {
                        Ok(v) => clock_skew_opt = Some(v),
                        Err(_) => {
                            emit_cli_error(
                                &format!("Invalid clock-skew value: {}", raw_args[i + 1]),
                                "INVALID_ARGUMENT",
                                "USAGE_ERROR",
                                EXIT_USAGE_ERROR,
                                Some(&raw_args[i + 1]),
                                None,
                                global_json,
                            );
                        }
                    }
                    i += 1;
                }
            }
            "--use-ctypes" => {
                // Accepted for Python CLI engine parity
            }
            "--enforce-aes" => {
                enforce_aes_opt = true;
            }
            "--stdout" => {
                stdout_opt = true;
            }
            "--opsec" => {
                opsec_opt = true;
            }
            "--dry-run" => {
                dry_run_opt = true;
            }
            "--all" => {
                purge_all_opt = true;
            }
            "--host" => {
                if i + 1 < raw_args.len() {
                    host_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--query" => {
                if i + 1 < raw_args.len() {
                    query_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--base-dn" => {
                if i + 1 < raw_args.len() {
                    base_dn_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                }
            }
            "--port" => {
                if i + 1 < raw_args.len() {
                    if let Ok(p) = raw_args[i + 1].parse::<u16>() {
                        port_opt = Some(p);
                    }
                    i += 1;
                }
            }
            cmd if explicit_command.is_none()
                && matches!(
                    cmd,
                    "keytab"
                        | "kcm"
                        | "triage"
                        | "ladder"
                        | "doctor"
                        | "token"
                        | "nhi"
                        | "config"
                        | "skill"
                        | "auth"
                        | "pac"
                        | "fix"
                        | "purge"
                        | "adcs"
                        | "ldap"
                ) =>
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
                opsec_opt,
            );
        }
        "pac" => {
            let target_source = file_opt.or_else(|| positional_args.first().cloned());
            handle_pac(target_source, global_json);
        }
        "fix" => {
            let target_kt = keytab_opt.or(file_opt);
            handle_fix(
                target_kt,
                realm_opt.as_deref(),
                kdc_opt.as_deref(),
                krb5_conf_opt.as_deref(),
                ccache_opt.as_deref(),
                dry_run_opt,
                clock_skew_opt.unwrap_or(300),
                global_json,
            );
        }
        "purge" => {
            let target_file = file_opt.or_else(|| positional_args.first().cloned());
            handle_purge(target_file, purge_all_opt, global_json);
        }
        "adcs" => {
            let target_source = file_opt.or_else(|| positional_args.first().cloned());
            handle_adcs(target_source, global_json);
        }
        "ldap" => {
            let host = host_opt.or_else(|| positional_args.first().cloned());
            let query = query_opt.unwrap_or_else(|| "spn".to_string());
            let base_dn = base_dn_opt.unwrap_or_else(|| "DC=corp,DC=local".to_string());
            let port = port_opt.unwrap_or(389);
            handle_ldap(host, &query, &base_dn, port, global_json);
        }
        "auth" => {
            let target_kt = keytab_opt.or(file_opt).or_else(|| positional_args.first().cloned());
            let target_princ = principal_opt.or_else(|| positional_args.get(1).cloned());
            let target_ccache = ccache_opt.or(out_opt);
            handle_auth(target_kt, target_princ, target_ccache, global_json, krb5_conf_opt);
        }
        "config" => {
            let out_target = out_opt.or(file_opt).or_else(|| positional_args.first().cloned());
            handle_config(
                realm_opt,
                keytab_opt,
                kdc_opt,
                admin_server_opt,
                out_target,
                stdout_opt,
                global_json,
                clock_skew_opt,
                enforce_aes_opt,
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
}

fn handle_config(
    realm_opt: Option<String>,
    keytab_opt: Option<String>,
    kdc_opt: Option<String>,
    admin_server_opt: Option<String>,
    out_path: Option<String>,
    stdout_mode: bool,
    json_output: bool,
    clock_skew_opt: Option<u32>,
    enforce_aes_opt: bool,
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

    let content = match generate_krb5_conf(&realm, &kdc, admin_server_opt.as_deref(), clock_skew_opt, enforce_aes_opt) {
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
    let default_kdc_admin = kdc.split(',').next().unwrap_or("").trim();
    let target_admin = admin_server_opt.as_deref().unwrap_or(default_kdc_admin);

    if json_output {
        let mut out = format!(
            "{{\n  \"status\": \"SUCCESS\",\n  \"realm\": \"{}\",\n  \"kdc\": \"{}\",\n  \"admin_server\": \"{}\",\n  \"config_path\": \"{}\",\n  \"export_command\": \"{}\"",
            clean_realm,
            kdc.trim(),
            target_admin,
            abs_str.replace('\\', "\\\\").replace('"', "\\\""),
            export_cmd.replace('\\', "\\\\").replace('"', "\\\""),
        );
        if let Some(skew) = clock_skew_opt {
            out.push_str(&format!(",\n  \"clockskew\": {}", skew));
        }
        if enforce_aes_opt {
            out.push_str(",\n  \"enforce_aes\": true");
        }
        out.push_str(&format!(",\n  \"content\": \"{}\"\n}}", tanuki::escape_json(&content)));
        println!("{}", out);
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
    println!("    ├─ Admin Server   : {}", target_admin);
    if let Some(skew) = clock_skew_opt {
        println!("    ├─ Clock Skew     : {}s (drift tolerance)", skew);
    }
    if enforce_aes_opt {
        println!("    ├─ Encryption     : AES-128/256 enforced (RC4 disabled)");
    }
    println!("    ╰─ Status         : Active configuration ready");
    println!("\n[+] To activate in your current session (unprivileged / no root required):");
    println!("    $ {}", export_cmd);
    println!("    $ kinit -k -t <keytab> <principal>");
}

fn handle_auth(
    keytab_path_opt: Option<String>,
    principal_opt: Option<String>,
    ccache_path_opt: Option<String>,
    json_output: bool,
    krb5_conf_opt: Option<String>,
) {
    let kt_path = match keytab_path_opt {
        Some(p) => p,
        None => {
            emit_cli_error(
                "Error: Keytab path required. Example: tanuki auth --keytab /etc/krb5.keytab --principal host/srv01@CORP.LOCAL",
                "MISSING_ARGUMENT",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                None,
                None,
                json_output,
            );
        }
    };

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

    let princ = match principal_opt {
        Some(p) => p,
        None => match fs::read(&kt_path) {
            Ok(bytes) => match parse_keytab_bytes(&bytes) {
                Ok(entries) => {
                    let mut found: Option<String> = None;
                    for e in entries {
                        if !e.principal.trim().is_empty() {
                            found = Some(e.principal);
                            break;
                        }
                    }
                    found.unwrap_or_else(|| {
                        emit_cli_error(
                            "No valid principal found within keytab file.",
                            "MISSING_PRINCIPAL",
                            "USAGE_ERROR",
                            EXIT_USAGE_ERROR,
                            Some(&kt_path),
                            None,
                            json_output,
                        );
                    })
                }
                Err(err) => {
                    emit_cli_error(
                        &format!("Error parsing keytab: {:?}", err),
                        "CORRUPT_KEYTAB",
                        "PARSE_FAILURE",
                        EXIT_PARSE_FAILURE,
                        Some(&kt_path),
                        None,
                        json_output,
                    );
                }
            },
            Err(err) => {
                emit_cli_error(
                    &format!("Cannot read keytab '{}': {}", kt_path, err),
                    "READ_ERROR",
                    "RESOURCE_MISSING",
                    EXIT_RESOURCE_MISSING,
                    Some(&kt_path),
                    None,
                    json_output,
                );
            }
        },
    };

    let ccache = ccache_path_opt
        .or_else(|| env::var("KRB5CCNAME").ok().map(|s| s.strip_prefix("FILE:").unwrap_or(&s).to_string()))
        .unwrap_or_else(|| "/tmp/krb5cc_1000".to_string());

    let mut cmd = process::Command::new("kinit");
    cmd.args(["-k", "-t", &kt_path, &princ])
        .env("KRB5CCNAME", format!("FILE:{}", ccache));
    if let Some(ref conf) = krb5_conf_opt {
        cmd.env("KRB5_CONFIG", conf);
    }
    let kinit_status = cmd.status();

    match kinit_status {
        Ok(status) if status.success() => {
            if json_output {
                println!(
                    "{{\n  \"status\": \"SUCCESS\",\n  \"method\": \"kinit\",\n  \"principal\": \"{}\",\n  \"keytab\": \"{}\",\n  \"ccache\": \"{}\",\n  \"export_command\": \"export KRB5CCNAME={}\"\n}}",
                    princ, kt_path, ccache, ccache
                );
            } else {
                print_card_header(
                    "TANUKI UNPRIVILEGED TICKET ACQUISITION",
                    Some("Method: kinit · Non-Interactive Authentication"),
                    72,
                );
                println!("[+] Principal      : {}", princ);
                println!("    ├─ Keytab File    : {}", kt_path);
                println!("    ├─ Credential CC  : {}", ccache);
                println!("    ╰─ Auth Method    : kinit");
                println!("\n[+] Active Credential Cache Export:\n    $ export KRB5CCNAME={}", ccache);
            }
        }
        _ => {
            emit_cli_error(
                "'kinit' utility not found on PATH or failed. Use Python engine 'tanuki auth' for zero-dependency ctypes acquisition.",
                "NO_AUTHENTICATION_BACKEND",
                "RESOURCE_MISSING",
                EXIT_RESOURCE_MISSING,
                Some(&kt_path),
                Some("Install krb5-user or run via python -m tanuki auth"),
                json_output,
            );
        }
    }
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
                }
            }
            None => {
                emit_cli_error(
                    &format!("No matching error resolution found for '{}'", q),
                    "UNKNOWN_ERROR_CODE",
                    "PROTOCOL_ERROR",
                    EXIT_RESOURCE_MISSING,
                    Some(q),
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
                    Some("11 Pre-compiled Protocol Vectors · Dual-Use Detection Telemetry"),
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
}

fn handle_doctor(
    json_output: bool,
    keytab_path: Option<String>,
    krb5_conf: Option<String>,
    sssd_pipe: Option<String>,
    sssd_pid: Option<String>,
    ccache_path: Option<String>,
    include_opsec: bool,
) {
    let opts = DoctorOptions {
        keytab_path: keytab_path.or_else(|| Some("/etc/krb5.keytab".to_string())),
        krb5_conf_path: krb5_conf.or_else(|| Some("/etc/krb5.conf".to_string())),
        sssd_pipe: sssd_pipe.or_else(|| Some("/var/lib/sss/pipes/kcm".to_string())),
        sssd_pid: sssd_pid.or_else(|| Some("/var/run/sssd.pid".to_string())),
        ccache_path,
        include_opsec,
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
                && (!c.get_extra_bool("is_secure_permissions", true)
                    || c.get_extra_bool("has_weak_enctypes", false))
        });
        if has_policy_stop {
            process::exit(EXIT_POLICY_STOP);
        }

        let has_missing_resource = report.checks.iter().any(|c| {
            (c.status == "FAIL" || c.status == "N_A")
                && !c.get_extra_bool("exists", true)
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
}

fn handle_pac(source_opt: Option<String>, json_output: bool) {
    let source = match source_opt {
        Some(s) => s,
        None => {
            emit_cli_error(
                "Error: PAC source required (file path, hex string, or base64). Example: tanuki pac ./ticket.pac",
                "MISSING_ARGUMENT",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                None,
                None,
                json_output,
            );
        }
    };

    match parse_pac_source(&source) {
        Ok(report) => {
            if json_output {
                println!("{}", pac_report_to_json(&report));
            } else {
                println!("{}", format_pac_report_terminal(&report));
            }
        }
        Err(err) => {
            emit_cli_error(
                &format!("Error decoding PAC: {}", err),
                "CORRUPT_PAC",
                "PARSE_FAILURE",
                EXIT_PARSE_FAILURE,
                Some(&source),
                Some(&err),
                json_output,
            );
        }
    }
}

fn handle_fix(
    keytab_path: Option<String>,
    realm: Option<&str>,
    kdc: Option<&str>,
    krb5_conf: Option<&str>,
    ccache_path: Option<&str>,
    dry_run: bool,
    clock_skew: u32,
    json_output: bool,
) {
    let res = run_fix(
        keytab_path.as_deref(),
        realm,
        kdc,
        krb5_conf,
        ccache_path,
        dry_run,
        clock_skew,
    );

    if json_output {
        println!("{}", res.to_json());
    } else {
        println!("{}", res.format_terminal());
    }

    if res.status == "ERROR" {
        process::exit(EXIT_POLICY_STOP);
    }
}

fn handle_purge(target_path: Option<String>, purge_all: bool, json_output: bool) {
    if target_path.is_none() && !purge_all {
        emit_cli_error(
            "Error: Purge requires either --all to purge all caches or a target file (--target <file>). Example: tanuki purge --all",
            "MISSING_ARGUMENT",
            "USAGE_ERROR",
            EXIT_USAGE_ERROR,
            None,
            None,
            json_output,
        );
    }

    if let Some(ref target) = target_path {
        let p = Path::new(target);
        let exists = p.exists() || fs::symlink_metadata(p).is_ok();
        if !exists {
            emit_cli_error(
                &format!("Error: Purge target not found: {}", target),
                "MISSING_TARGET_FILE",
                "RESOURCE_MISSING",
                EXIT_RESOURCE_MISSING,
                Some(target),
                None,
                json_output,
            );
        }
        if p.is_dir() {
            emit_cli_error(
                &format!("Error: Purge target is a directory, not a file: {}", target),
                "INVALID_TARGET_DIRECTORY",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                Some(target),
                None,
                json_output,
            );
        }
    }

    let res = run_purge(target_path.as_deref(), purge_all);
    if json_output {
        println!("{}", res.to_json());
    } else {
        println!("{}", res.format_terminal());
    }

    if res.status != "SUCCESS" {
        process::exit(EXIT_PARSE_FAILURE);
    }
}

fn handle_adcs(source_opt: Option<String>, json_output: bool) {
    let source = match source_opt {
        Some(s) => s,
        None => {
            emit_cli_error(
                "Error: AD CS template or certificate source required. Example: tanuki adcs --file templates.json",
                "MISSING_ARGUMENT",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                None,
                None,
                json_output,
            );
        }
    };

    match scan_adcs_source(&source) {
        Ok(rep) => {
            if json_output {
                println!("{}", rep.to_json());
            } else {
                println!("{}", rep.format_terminal());
            }
        }
        Err(err) => {
            emit_cli_error(
                &format!("Error scanning AD CS source: {}", err),
                "ADCS_SCAN_ERROR",
                "PARSE_FAILURE",
                EXIT_PARSE_FAILURE,
                Some(&source),
                Some(&err),
                json_output,
            );
        }
    }
}

fn handle_ldap(
    host_opt: Option<String>,
    query_type: &str,
    base_dn: &str,
    port: u16,
    json_output: bool,
) {
    let host = match host_opt {
        Some(h) => h,
        None => {
            emit_cli_error(
                "Error: LDAP host/DC address required. Example: tanuki ldap --host 192.168.56.106",
                "MISSING_ARGUMENT",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                None,
                None,
                json_output,
            );
        }
    };

    let rep = query_active_directory_ldap(&host, query_type, base_dn, port, 5);
    if json_output {
        println!("{}", rep.to_json());
    } else {
        println!("{}", rep.format_terminal());
    }

    if rep.status == "BIND_FAILED" || rep.status == "CONNECTION_FAILED" {
        process::exit(EXIT_RESOURCE_MISSING);
    }
}

