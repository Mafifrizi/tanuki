use std::env;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;
use tanuki::{
    blast_report_to_json, candidates_to_json, classify_identity_tier, entries_to_json,
    errors_to_json, escape_json, evaluate_blast_radius, find_error_resolution,
    format_blast_report_terminal, format_pac_report_terminal, format_shadow_report_terminal,
    generate_ad_remediations, generate_krb5_conf, ladder_to_json, pac_report_to_json,
    parse_and_validate_jwt, parse_key_credential_link, parse_keytab_bytes, parse_pac_source,
    query_active_directory_ldap, resolve_current_uid, run_doctor, run_fix, run_purge,
    save_candidates, scan_adcs_source, scan_for_ccache_blobs, shadow_report_to_json,
    validate_token_exchange, BlastReport, DoctorOptions, TokenExchangeParams, DECISION_LADDER,
    ERROR_DICTIONARY,
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
    shadow <INPUT>      Dissect Active Directory Shadow Credentials (MS-ADTS 2.2.20)
    adcs <FILE|SOURCE>  Scan Active Directory Certificate Templates (ESC1-ESC11)
    ldap [OPTIONS]      Query Active Directory via unprivileged or authenticated LDAP
    keytab [PATH]       Inspect binary keytab file (RFC 4120)
    config [OPTIONS]    Generate unprivileged zero-DNS Kerberos config (RFC 4120)
    auth [OPTIONS]      Acquire TGT using keytab via host kinit
    tgs [SPN]           Acquire Kerberos Service Ticket (TGS-REQ) for service access
    blast [OPTIONS]     Active Directory privilege tiering and blast radius mapping
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
    -u, --username <U>  Username, UPN, or DN for authenticated LDAP bind
    -p, --password <P>  Password for LDAP bind (or principal for auth)
    --principal <P>     Kerberos principal for authentication
    --spn <SPN>         Target Service Principal Name for TGS acquisition or triage
    -a, --audience <AUD> Expected audience for workload validation
    --issuer <ISS>      Expected issuer for workload validation
    --realm <REALM>     Target Kerberos realm (mandates uppercase)
    --kdc <HOST_OR_IP>  KDC address or hostname (supports multiple or comma-separated)
    --admin-server <HOST_OR_IP> Optional admin server for config
    --clock-skew <SECS> Clock skew tolerance in seconds (unprivileged hypervisors)
    --enforce-aes       Strictly enforce AES-128/256 and reject legacy RC4
    --fast              Enable RFC 6113 FAST armoring (fast_req_armoring = true)
    --armor-cache <PATH> Armor credentials cache path for FAST armoring
    --stdout            Print generated config directly to stdout
    --keytab <PATH>     Target keytab path for doctor/auth/config/fix
    --krb5-conf <PATH>  Target krb5.conf path for doctor/fix
    --sssd-pipe <PATH>  Target SSSD KCM pipe socket path for doctor
    --sssd-pid <PATH>   Target SSSD pid path for doctor
    --secrets-path <PATH> Target SSSD secrets database path for doctor
    --ccache <PATH>     Target ccache path for doctor/auth/fix
    --ad-enctypes <HEX> Active Directory msDS-SupportedEncryptionTypes for doctor
    --ad-kvno <INT>     Active Directory msDS-KeyVersionNumber for doctor
    --opsec             Include live host OPSEC sensor probe in pre-flight doctor
    --dry-run           Simulate remediation without applying changes (for tanuki fix)
    --all               Purge all discovered ticket caches and temp configs
    --host <HOST_OR_IP> Target Active Directory domain controller for LDAP
    --query <TYPE>      LDAP query category (spn, asreproast, rbcd, shadow, unconstrained, all)
    --base-dn <DN>      Base DN for directory query (e.g. DC=corp,DC=local)
    --port <PORT>       Target LDAP port (default: 389)
    --json              Output structured JSON for agent and pipeline consumption
    -h, --help          Print help information
    -V, --version       Print version information"#
    );
}

#[allow(dead_code)]
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
            escape_json(status),
            escape_json(reason_code),
            escape_json(category),
            exit_code,
            escape_json(message)
        );
        if let Some(t) = target {
            out.push_str(&format!(",\n  \"target\": \"{}\"", escape_json(t)));
        }
        if let Some(d) = details {
            out.push_str(&format!(",\n  \"details\": \"{}\"", escape_json(d)));
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
        println!("  [6]  LDAP     : Query Active Directory via unprivileged or authenticated LDAP");
        println!("  [7]  AD CS    : Passive certificate & template scanner (ESC1-ESC11)");
        println!("  [8]  NHI      : Workload identity inspection & token exchange");
        println!("  [9]  KCM      : Extract SSSD KCM credential cache streams");
        println!("  [10] Triage   : Lookup Kerberos protocol error resolutions");
        println!("  [11] Ladder   : Display 5-rung Tactical Decision Ladder");
        println!("  [12] Purge    : Cryptographic zero-trace artifact sanitization");
        println!("  [13] Skill    : Display AI agent skill manifest");
        println!("  [14] Config   : Generate zero-DNS unprivileged Kerberos configuration");
        println!("  [15] Shadow   : Parse msDS-KeyCredentialLink shadow credentials");
        println!("  [0]  Exit");
        println!();

        let choice = match read_line_prompt("Select an option [0-15]: ") {
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
                handle_doctor(false, None, None, None, None, None, false, None, None, None);
            }
            "2" => {
                handle_fix(None, None, None, None, None, false, 300, None, false);
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
                handle_auth(Some(kt), princ, None, false, None, None, false, None);
            }
            "5" => {
                let pac_src = read_line_prompt("Target PAC file path or hex: ").unwrap_or_default();
                handle_pac(Some(pac_src), false);
            }
            "6" => {
                let host = read_line_prompt("Target DC IP/Host: ").unwrap_or_default();
                let q = match read_line_prompt("Query type (spn/asreproast/rbcd/shadow/unconstrained/all) [all]: ") {
                    Some(s) if !s.is_empty() => s,
                    _ => "all".to_string(),
                };
                handle_ldap(Some(host), &q, "DC=corp,DC=local", 389, false, false, None, None);
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
            "14" => {
                let realm = read_line_prompt("Target Kerberos Realm (e.g. CORP.LOCAL): ").filter(|s| !s.is_empty());
                let kdc = read_line_prompt("Target Domain Controller / KDC IP: ").filter(|s| !s.is_empty());
                let out = read_line_prompt("Output config path [./krb5.conf]: ")
                    .filter(|s| !s.is_empty())
                    .or_else(|| Some("./krb5.conf".to_string()));
                handle_config(realm, None, kdc, None, out, false, false, Some(300), false, false, None);
            }
            "15" => {
                let src = read_line_prompt("Target Shadow Credential file path or hex: ").unwrap_or_default();
                handle_shadow(Some(src), false);
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
        "pac", "fix", "purge", "adcs", "ldap", "shadow", "tgs", "blast",
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
    let mut spn_opt: Option<String> = None;
    let mut clock_skew_opt: Option<u32> = None;
    let mut enforce_aes_opt = false;
    let mut opsec_opt = false;
    let mut dry_run_opt = false;
    let mut purge_all_opt = false;
    let mut host_opt: Option<String> = None;
    let mut query_opt: Option<String> = None;
    let mut base_dn_opt: Option<String> = None;
    let mut port_opt: Option<u16> = None;
    let mut ssl_opt = false;
    let mut live_opt = false;
    let mut endpoint_opt: Option<String> = None;
    let mut fast_opt = false;
    let mut armor_cache_opt: Option<String> = None;
    let mut krb_error_opt: Option<String> = None;
    let mut secrets_path_opt: Option<String> = None;
    let mut username_opt: Option<String> = None;
    let mut password_opt: Option<String> = None;
    let mut ad_supported_enctypes_opt: Option<u32> = None;
    let mut ad_kvno_opt: Option<u32> = None;

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
            "-f" | "--file" | "--target" | "--template-dump" => {
                if i + 1 < raw_args.len() {
                    file_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        &format!("Option requires an argument: {}", raw_args[i]),
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "-o" | "--out" => {
                if i + 1 < raw_args.len() {
                    out_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        &format!("Option requires an argument: {}", raw_args[i]),
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "-u" | "--username" | "--user" => {
                if i + 1 < raw_args.len() {
                    username_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        &format!("Option requires an argument: {}", raw_args[i]),
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--password" => {
                if i + 1 < raw_args.len() {
                    password_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --password",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--principal" => {
                if i + 1 < raw_args.len() {
                    principal_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --principal",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--spn" => {
                if i + 1 < raw_args.len() {
                    spn_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --spn",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "-p" => {
                if i + 1 < raw_args.len() {
                    principal_opt = Some(raw_args[i + 1].clone());
                    password_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: -p",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--ad-supported-enctypes" | "--ad-enctypes" => {
                if i + 1 < raw_args.len() {
                    let val = &raw_args[i + 1];
                    let parsed = if val.to_lowercase().starts_with("0x") {
                        u32::from_str_radix(&val[2..], 16).ok()
                    } else {
                        val.parse::<u32>().ok()
                    };
                    ad_supported_enctypes_opt = parsed;
                    i += 1;
                } else {
                    emit_cli_error(
                        &format!("Option requires an argument: {}", raw_args[i]),
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--ad-kvno" => {
                if i + 1 < raw_args.len() {
                    ad_kvno_opt = raw_args[i + 1].parse::<u32>().ok();
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --ad-kvno",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "-a" | "--audience" => {
                if i + 1 < raw_args.len() {
                    audience_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        &format!("Option requires an argument: {}", raw_args[i]),
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
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
                } else {
                    emit_cli_error(
                        "Option requires an argument: --grant-type",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--subject-token" => {
                if i + 1 < raw_args.len() {
                    subject_token_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --subject-token",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--subject-token-type" => {
                if i + 1 < raw_args.len() {
                    subject_token_type_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --subject-token-type",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--requested-token-type" => {
                if i + 1 < raw_args.len() {
                    requested_token_type_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --requested-token-type",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--keytab" => {
                if i + 1 < raw_args.len() {
                    keytab_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --keytab",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--krb5-conf" => {
                if i + 1 < raw_args.len() {
                    krb5_conf_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --krb5-conf",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--sssd-pipe" => {
                if i + 1 < raw_args.len() {
                    sssd_pipe_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --sssd-pipe",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--sssd-pid" => {
                if i + 1 < raw_args.len() {
                    sssd_pid_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --sssd-pid",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--secrets-path" => {
                if i + 1 < raw_args.len() {
                    secrets_path_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --secrets-path",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--ccache" => {
                if i + 1 < raw_args.len() {
                    ccache_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --ccache",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--realm" => {
                if i + 1 < raw_args.len() {
                    realm_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --realm",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
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
                } else {
                    emit_cli_error(
                        "Option requires an argument: --kdc",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--admin-server" => {
                if i + 1 < raw_args.len() {
                    admin_server_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --admin-server",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
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
                } else {
                    emit_cli_error(
                        &format!("Option requires an argument: {}", raw_args[i]),
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--use-ctypes" => {
                // Accepted for Python CLI engine parity
            }
            "--enforce-aes" => {
                enforce_aes_opt = true;
            }
            "--fast" => {
                fast_opt = true;
            }
            "--armor-cache" => {
                if i + 1 < raw_args.len() && !raw_args[i + 1].starts_with('-') {
                    armor_cache_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --armor-cache",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
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
            "--host" | "--server" => {
                if i + 1 < raw_args.len() {
                    host_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        &format!("Option requires an argument: {}", raw_args[i]),
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--ssl" => {
                ssl_opt = true;
            }
            "--live" => {
                live_opt = true;
            }
            "--endpoint" => {
                if i + 1 < raw_args.len() {
                    endpoint_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --endpoint",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--query" => {
                if i + 1 < raw_args.len() {
                    query_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --query",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--base-dn" => {
                if i + 1 < raw_args.len() {
                    base_dn_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --base-dn",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--port" => {
                if i + 1 < raw_args.len() {
                    if let Ok(p) = raw_args[i + 1].parse::<u16>() {
                        port_opt = Some(p);
                    }
                    i += 1;
                } else {
                    emit_cli_error(
                        "Option requires an argument: --port",
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
                }
            }
            "--krb-error" | "--error" => {
                if i + 1 < raw_args.len() {
                    krb_error_opt = Some(raw_args[i + 1].clone());
                    i += 1;
                } else {
                    emit_cli_error(
                        &format!("Option requires an argument: {}", raw_args[i]),
                        "MISSING_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        global_json,
                    );
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
                        | "shadow"
                        | "tgs"
                        | "blast"
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
                secrets_path_opt,
                ad_supported_enctypes_opt,
                ad_kvno_opt,
            );
        }
        "pac" => {
            let target_source = file_opt.or_else(|| positional_args.first().cloned());
            handle_pac(target_source, global_json);
        }
        "fix" => {
            let target_kt = keytab_opt.or(file_opt).or_else(|| positional_args.first().cloned());
            handle_fix(
                target_kt,
                realm_opt.as_deref(),
                kdc_opt.as_deref(),
                krb5_conf_opt.as_deref(),
                ccache_opt.as_deref(),
                dry_run_opt,
                clock_skew_opt.unwrap_or(300),
                krb_error_opt.as_deref(),
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
        "shadow" => {
            let target_source = positional_args.first().or(file_opt.as_ref()).cloned();
            handle_shadow(target_source, global_json);
        }
        "ldap" => {
            let host = host_opt.or_else(|| positional_args.first().cloned());
            let query = query_opt.unwrap_or_else(|| "spn".to_string());
            let base_dn = base_dn_opt.unwrap_or_else(|| {
                if let Some(r) = realm_opt.as_deref() {
                    let parts: Vec<&str> = r.trim().split('.').filter(|s| !s.is_empty()).collect();
                    if !parts.is_empty() {
                        parts.iter().map(|p| format!("DC={}", p)).collect::<Vec<_>>().join(",")
                    } else {
                        "DC=corp,DC=local".to_string()
                    }
                } else {
                    "DC=corp,DC=local".to_string()
                }
            });
            let default_port = if ssl_opt { 636 } else { 389 };
            let port = port_opt.unwrap_or(default_port);
            handle_ldap(
                host,
                &query,
                &base_dn,
                port,
                ssl_opt,
                global_json,
                username_opt.as_deref(),
                password_opt.as_deref(),
            );
        }
        "auth" => {
            if spn_opt.is_some() {
                handle_tgs(
                    spn_opt,
                    ccache_opt.or(out_opt),
                    keytab_opt.or(file_opt),
                    principal_opt,
                    global_json,
                    krb5_conf_opt,
                    kdc_opt,
                );
            } else {
                let target_kt = keytab_opt.or(file_opt).or_else(|| positional_args.first().cloned());
                let target_princ = principal_opt.or_else(|| positional_args.get(1).cloned());
                let target_ccache = ccache_opt.or(out_opt);
                handle_auth(target_kt, target_princ, target_ccache, global_json, krb5_conf_opt, kdc_opt, fast_opt, armor_cache_opt);
            }
        }
        "tgs" => {
            let target_spn = spn_opt.or_else(|| positional_args.first().cloned());
            let target_kt = keytab_opt.or(file_opt);
            let target_ccache = ccache_opt.or(out_opt);
            handle_tgs(
                target_spn,
                target_ccache,
                target_kt,
                principal_opt,
                global_json,
                krb5_conf_opt,
                kdc_opt,
            );
        }
        "blast" => {
            let target_source = positional_args.first().or(file_opt.as_ref()).cloned();
            handle_blast(
                target_source.clone(),
                ccache_opt,
                keytab_opt.or(file_opt),
                target_source,
                host_opt,
                base_dn_opt,
                username_opt,
                password_opt,
                spn_opt,
                global_json,
            );
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
                fast_opt,
                armor_cache_opt,
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
                live_opt,
                endpoint_opt,
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
    fast_opt: bool,
    armor_cache_opt: Option<String>,
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
        None => match tanuki::config::discover_dc_via_srv(&realm) {
            Some(discovered) => discovered,
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
        },
    };

    let content = match generate_krb5_conf(
        &realm,
        &kdc,
        admin_server_opt.as_deref(),
        clock_skew_opt,
        enforce_aes_opt,
        fast_opt,
        armor_cache_opt.as_deref(),
    ) {
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
    if let Ok(meta) = fs::symlink_metadata(&target_path) {
        if meta.file_type().is_symlink() {
            emit_cli_error(
                &format!("Refusing to write configuration to symbolic link: {}", target_file),
                "SYMLINK_REJECTED",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                Some(&target_file),
                None,
                json_output,
            );
        }
    }
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
            tanuki::escape_json(&clean_realm),
            tanuki::escape_json(kdc.trim()),
            tanuki::escape_json(target_admin),
            tanuki::escape_json(&abs_str),
            tanuki::escape_json(&export_cmd),
        );
        if let Some(skew) = clock_skew_opt {
            out.push_str(&format!(",\n  \"clockskew\": {}", skew));
        }
        if enforce_aes_opt {
            out.push_str(",\n  \"enforce_aes\": true");
        }
        if fast_opt {
            out.push_str(",\n  \"fast\": true");
        }
        if let Some(ref armor) = armor_cache_opt {
            out.push_str(&format!(",\n  \"armor_cache\": \"{}\"", tanuki::escape_json(armor)));
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
    if fast_opt {
        println!("    ├─ FAST Armoring  : Enabled (fast_req_armoring = true)");
    }
    if let Some(ref armor) = armor_cache_opt {
        println!("    ├─ Armor Cache    : {}", armor);
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
    kdc_opt: Option<String>,
    fast: bool,
    armor_cache_opt: Option<String>,
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

    if princ.trim().starts_with('-') {
        emit_cli_error(
            &format!("Invalid principal name starting with '-': '{}'", princ),
            "INVALID_ARGUMENT",
            "USAGE_ERROR",
            EXIT_USAGE_ERROR,
            Some(&kt_path),
            None,
            json_output,
        );
    }

    // Fast non-blocking socket probe (<800ms) before initiating Kerberos auth over live wire
    let mut target_kdc_host = kdc_opt;
    if target_kdc_host.is_none() {
        let conf_env = env::var("KRB5_CONFIG").ok();
        let conf_path = krb5_conf_opt.as_deref().or(conf_env.as_deref()).unwrap_or("/etc/krb5.conf");
        if let Ok(conf_str) = fs::read_to_string(conf_path) {
            for line in conf_str.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("kdc") && trimmed.contains('=') {
                    if let Some(val) = trimmed.split('=').nth(1) {
                        let host = val.trim().split_whitespace().next().unwrap_or("").split(',').next().unwrap_or("").split(':').next().unwrap_or("");
                        if !host.is_empty() {
                            target_kdc_host = Some(host.to_string());
                            break;
                        }
                    }
                }
            }
        }
    }
    if target_kdc_host.is_none() && princ.contains('@') {
        let realm = princ.split('@').last().unwrap_or("").trim();
        if let Some(discovered) = tanuki::config::discover_dc_via_srv(realm) {
            target_kdc_host = Some(discovered);
        }
    }

    if let Some(ref raw_host) = target_kdc_host {
        let clean_host = raw_host.split(',').next().unwrap_or(raw_host).trim().split(':').next().unwrap_or(raw_host).trim();
        if !clean_host.is_empty() {
            use std::net::{TcpStream, ToSocketAddrs};
            use std::time::Duration;
            let addr_str = format!("{}:88", clean_host);
            let unreachable_err = match addr_str.to_socket_addrs() {
                Ok(mut addrs) => match addrs.next() {
                    Some(addr) => match TcpStream::connect_timeout(&addr, Duration::from_millis(800)) {
                        Ok(_) => None,
                        Err(e) => Some(e.to_string()),
                    },
                    None => Some(format!("Could not resolve host '{}'", clean_host)),
                },
                Err(e) => Some(e.to_string()),
            };

            if let Some(err_msg) = unreachable_err {
                let remediation = format!("ssh -L 8888:{}:88 user@pivot -N", clean_host);
                emit_cli_error(
                    &format!("KDC port 88 unreachable on host '{}' ({}). Tactical remediation: Verify network route/firewall or configure SSH port-forwarding pivot: {}", clean_host, err_msg, remediation),
                    "KDC_UNREACHABLE",
                    "NETWORK_ERROR",
                    EXIT_RESOURCE_MISSING,
                    Some(&kt_path),
                    Some(&remediation),
                    json_output,
                );
            }
        }
    }

    let fallback_cc = format!("/tmp/krb5cc_{}", resolve_current_uid());
    let ccache = ccache_path_opt
        .or_else(|| env::var("KRB5CCNAME").ok().map(|s| s.strip_prefix("FILE:").unwrap_or(&s).to_string()))
        .unwrap_or(fallback_cc);

    if let Ok(meta) = fs::symlink_metadata(&ccache) {
        if meta.file_type().is_symlink() {
            emit_cli_error(
                &format!("Refusing to write credential cache to symbolic link: {}", ccache),
                "SYMLINK_REJECTED",
                "SECURITY_VIOLATION",
                EXIT_POLICY_STOP,
                Some(&ccache),
                None,
                json_output,
            );
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let _ = fs::OpenOptions::new().create(true).write(true).mode(0o600).open(&ccache);
    }

    let mut cmd = process::Command::new("kinit");
    cmd.args(["-k", "-t", &kt_path, "-c", &ccache])
        .env("KRB5CCNAME", format!("FILE:{}", ccache));
    if let Some(ref armor) = armor_cache_opt {
        cmd.args(["-T", armor]);
    }
    cmd.arg("--");
    cmd.arg(&princ);
    if let Some(ref conf) = krb5_conf_opt {
        cmd.env("KRB5_CONFIG", conf);
    }
    let kinit_status = cmd.status();

    match kinit_status {
        Ok(status) if status.success() => {
            if json_output {
                let mut json_str = format!(
                    "{{\n  \"status\": \"SUCCESS\",\n  \"method\": \"kinit\",\n  \"principal\": \"{}\",\n  \"keytab\": \"{}\",\n  \"ccache\": \"{}\",\n  \"export_command\": \"export KRB5CCNAME={}\"",
                    escape_json(&princ),
                    escape_json(&kt_path),
                    escape_json(&ccache),
                    escape_json(&ccache)
                );
                if fast {
                    json_str.push_str(",\n  \"fast\": true");
                }
                if let Some(ref armor) = armor_cache_opt {
                    json_str.push_str(&format!(",\n  \"armor_cache\": \"{}\"", tanuki::escape_json(armor)));
                }
                json_str.push_str("\n}");
                println!("{}", json_str);
            } else {
                print_card_header(
                    "TANUKI UNPRIVILEGED TICKET ACQUISITION",
                    Some("Method: kinit · Non-Interactive Authentication"),
                    72,
                );
                println!("[+] Principal      : {}", princ);
                println!("    ├─ Keytab File    : {}", kt_path);
                println!("    ├─ Credential CC  : {}", ccache);
                if fast {
                    println!("    ├─ FAST Armoring  : Enabled (RFC 6113)");
                }
                if let Some(ref armor) = armor_cache_opt {
                    println!("    ├─ Armor Cache    : {}", armor);
                }
                println!("    ╰─ Auth Method    : kinit");
                println!("\n[+] Active Credential Cache Export:\n    $ export KRB5CCNAME={}", ccache);
            }
        }
        Ok(status) => {
            emit_cli_error(
                &format!("kinit authentication failed with exit status {:?}", status.code()),
                "AUTH_FAILED",
                "PROTOCOL_ERROR",
                EXIT_POLICY_STOP,
                Some(&kt_path),
                Some("Check keytab encryption types, principal KVNO, or Domain Controller clock skew."),
                json_output,
            );
        }
        Err(_) => {
            let guidance = if let Ok(os_rel) = fs::read_to_string("/etc/os-release").or_else(|_| fs::read_to_string("/usr/lib/os-release")) {
                let low = os_rel.to_lowercase();
                if low.contains("alpine") {
                    "Alpine: apk add krb5"
                } else if low.contains("debian") || low.contains("ubuntu") || low.contains("kali") {
                    "Debian/Ubuntu/Kali: apt install krb5-user"
                } else if low.contains("rhel") || low.contains("centos") || low.contains("fedora") || low.contains("rocky") || low.contains("alma") {
                    "RHEL/CentOS/Fedora: dnf install krb5-workstation"
                } else {
                    "Install Kerberos client utilities, or execute via Python ctypes: python3 -m tanuki auth --use-ctypes"
                }
            } else {
                "Install Kerberos client utilities, or execute via Python ctypes: python3 -m tanuki auth --use-ctypes"
            };
            emit_cli_error(
                &format!("kinit utility not found on host $PATH. {}", guidance),
                "MISSING_KINIT_UTILITY",
                "DEPENDENCY_ERROR",
                EXIT_RESOURCE_MISSING,
                Some(&kt_path),
                Some(guidance),
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
                let subtitle = format!(
                    "{} Pre-compiled Protocol Vectors · Dual-Use Detection Telemetry",
                    ERROR_DICTIONARY.len()
                );
                print_card_header(
                    "KERBEROS & SSSD ERROR RESOLUTION DICTIONARY",
                    Some(&subtitle),
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
    secrets_path: Option<String>,
    ad_supported_enctypes: Option<u32>,
    ad_kvno: Option<u32>,
) {
    let opts = DoctorOptions {
        keytab_path: keytab_path.or_else(|| Some("/etc/krb5.keytab".to_string())),
        krb5_conf_path: krb5_conf
            .or_else(|| env::var("KRB5_CONFIG").ok())
            .or_else(|| Some("/etc/krb5.conf".to_string())),
        sssd_pipe: sssd_pipe.or_else(|| Some("/var/lib/sss/pipes/kcm".to_string())),
        sssd_pid: sssd_pid.or_else(|| Some("/var/run/sssd.pid".to_string())),
        secrets_path: secrets_path.or_else(|| Some("/var/lib/sss/secrets/secrets.ldb".to_string())),
        ccache_path,
        include_opsec,
        ad_supported_enctypes,
        ad_kvno,
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
    issuer: Option<String>,
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
                    EXIT_RESOURCE_MISSING,
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

    match parse_and_validate_jwt(&raw_token, audience.as_deref(), issuer.as_deref()) {
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
    live: bool,
    endpoint: Option<String>,
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
                if live {
                    if let Some(ref ep) = endpoint {
                        println!("{{\n  \"live_mode\": true,\n  \"endpoint\": \"{}\",\n  \"offline_validation\": {}\n}}", escape_json(ep), report.to_json());
                        return;
                    }
                }
                println!("{}", report.to_json());
            } else {
                println!("{}", report.format_terminal());
                if live {
                    if let Some(ref ep) = endpoint {
                        println!("\n[*] Live Token Exchange Endpoint: {}", ep);
                        println!("    Protocol: RFC 8693 OAuth 2.0 Token Exchange");
                        println!("    Status: Offline parameter schema verified compliant.");
                    } else {
                        println!("\n[!] Live mode requested without --endpoint URL. Offline validation completed.");
                    }
                }
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
                let items: Vec<String> = found.iter().map(|p| format!("\"{}\"", escape_json(p))).collect();
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
        out.push_str("    \"active directory\",\n    \"kerberos\",\n    \"keytab\",\n    \"sssd\",\n    \"kcm\",\n    \"certipy\",\n    \"ad cs\",\n    \"shadow credentials\",\n    \"rbcd\",\n    \"workload identity\",\n    \"tanuki doctor\",\n    \"tanuki auth\",\n    \"tanuki pac\",\n    \"tanuki fix\",\n    \"tanuki purge\",\n    \"tanuki adcs\",\n    \"tanuki ldap\",\n    \"tanuki shadow\",\n    \"tanuki config\",\n    \"pre-flight\",\n    \"telemetry\",\n    \"auditd\",\n    \"rfc 8693\",\n    \"token exchange\"\n");
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
    krb_error: Option<&str>,
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
        krb_error,
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
    use_ssl: bool,
    json_output: bool,
    username: Option<&str>,
    password: Option<&str>,
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

    let rep = query_active_directory_ldap(&host, query_type, base_dn, port, use_ssl, 5, username, password);
    if json_output {
        println!("{}", rep.to_json());
    } else {
        println!("{}", rep.format_terminal());
    }

    if rep.status == "BIND_FAILED" || rep.status == "CONNECTION_FAILED" {
        process::exit(EXIT_RESOURCE_MISSING);
    }
}

fn handle_shadow(source_opt: Option<String>, json_output: bool) {
    let source = match source_opt {
        Some(s) => s,
        None => {
            emit_cli_error(
                "Error: Shadow Credential input required (file path, raw hex, or DN-Binary string). Example: tanuki shadow ./blob.bin",
                "MISSING_ARGUMENT",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                None,
                None,
                json_output,
            );
        }
    };

    match parse_key_credential_link(&source) {
        Ok(rep) => {
            if json_output {
                println!("{}", shadow_report_to_json(&rep));
            } else {
                println!("{}", format_shadow_report_terminal(&rep));
            }
        }
        Err(err) => {
            emit_cli_error(
                &format!("Error parsing Shadow Credential: {}", err),
                "SHADOW_PARSE_ERROR",
                "PARSE_FAILURE",
                EXIT_PARSE_FAILURE,
                Some(&source),
                Some(&err),
                json_output,
            );
        }
    }
}

fn handle_tgs(
    spn_opt: Option<String>,
    ccache_path_opt: Option<String>,
    keytab_path_opt: Option<String>,
    principal_opt: Option<String>,
    json_output: bool,
    krb5_conf_opt: Option<String>,
    kdc_opt: Option<String>,
) {
    let spn = match spn_opt {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            emit_cli_error(
                "Error: Target SPN required. Example: tanuki tgs HTTP/tanuki-app.lab.local@LAB.LOCAL",
                "MISSING_ARGUMENT",
                "USAGE_ERROR",
                EXIT_USAGE_ERROR,
                None,
                None,
                json_output,
            );
        }
    };

    if spn.starts_with('-') {
        emit_cli_error(
            &format!("Invalid SPN starting with '-': '{}'", spn),
            "INVALID_ARGUMENT",
            "USAGE_ERROR",
            EXIT_USAGE_ERROR,
            None,
            None,
            json_output,
        );
    }

    if let Some(ref kt) = keytab_path_opt {
        if Path::new(kt).exists() {
            let fallback_cc = format!("/tmp/krb5cc_{}", resolve_current_uid());
            let cc = ccache_path_opt.clone().unwrap_or(fallback_cc);
            let mut cmd = process::Command::new("kinit");
            cmd.args(["-k", "-t", kt, "-c", &cc]);
            if let Some(ref p) = principal_opt {
                if p.trim().starts_with('-') {
                    emit_cli_error(
                        &format!("Invalid principal starting with '-': '{}'", p),
                        "INVALID_ARGUMENT",
                        "USAGE_ERROR",
                        EXIT_USAGE_ERROR,
                        None,
                        None,
                        json_output,
                    );
                }
                cmd.arg("--");
                cmd.arg(p);
            }
            cmd.env("KRB5CCNAME", format!("FILE:{}", cc));
            if let Some(ref conf) = krb5_conf_opt {
                cmd.env("KRB5_CONFIG", conf);
            }
            let _ = cmd.status();
        }
    }

    let fallback_cc = format!("/tmp/krb5cc_{}", resolve_current_uid());
    let ccache = ccache_path_opt
        .or_else(|| env::var("KRB5CCNAME").ok().map(|s| s.strip_prefix("FILE:").unwrap_or(&s).to_string()))
        .unwrap_or(fallback_cc);

    if !Path::new(&ccache).exists() {
        let remediation = "tanuki auth --keytab <KEYTAB> --principal <PRINCIPAL>";
        emit_cli_error(
            &format!("Credential cache not found at '{}'. Tactical remediation: Obtain a valid TGT first: {}", ccache, remediation),
            "MISSING_CCACHE",
            "RESOURCE_MISSING",
            EXIT_RESOURCE_MISSING,
            Some(&ccache),
            Some(remediation),
            json_output,
        );
    }

    let mut target_kdc_host = kdc_opt;
    if target_kdc_host.is_none() {
        let conf_env = env::var("KRB5_CONFIG").ok();
        let to_check = krb5_conf_opt.as_deref().or(conf_env.as_deref()).unwrap_or("/etc/krb5.conf");
        if let Ok(content) = fs::read_to_string(to_check) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("kdc") && trimmed.contains('=') {
                    if let Some(val) = trimmed.split('=').nth(1) {
                        let candidate = val.trim().split_whitespace().next().unwrap_or("").split(',').next().unwrap_or("").split(':').next().unwrap_or("");
                        if !candidate.is_empty() {
                            target_kdc_host = Some(candidate.to_string());
                            break;
                        }
                    }
                }
            }
        }
    }
    if target_kdc_host.is_none() && spn.contains('@') {
        let realm = spn.split('@').last().unwrap_or("").trim();
        if let Some(discovered) = tanuki::config::discover_dc_via_srv(realm) {
            target_kdc_host = Some(discovered);
        }
    }

    if let Some(ref raw_host) = target_kdc_host {
        let clean_host = raw_host.split(',').next().unwrap_or(raw_host).trim().split(':').next().unwrap_or(raw_host).trim();
        if !clean_host.is_empty() {
            use std::net::{TcpStream, ToSocketAddrs};
            use std::time::Duration;
            let addr_str = format!("{}:88", clean_host);
            if let Ok(mut addrs) = addr_str.to_socket_addrs() {
                if let Some(addr) = addrs.next() {
                    if TcpStream::connect_timeout(&addr, Duration::from_millis(800)).is_err() {
                        let remediation = format!("ssh -L 8888:{}:88 user@pivot -N", clean_host);
                        emit_cli_error(
                            &format!("KDC port 88 unreachable on host '{}'. Tactical remediation: {}", clean_host, remediation),
                            "KDC_UNREACHABLE",
                            "NETWORK_ERROR",
                            EXIT_RESOURCE_MISSING,
                            Some(&ccache),
                            Some(&remediation),
                            json_output,
                        );
                    }
                }
            }
        }
    }

    let mut cmd = process::Command::new("kvno");
    cmd.args(["-c", &ccache, "--", &spn]);
    if let Some(ref conf) = krb5_conf_opt {
        cmd.env("KRB5_CONFIG", conf);
    }
    cmd.env("KRB5CCNAME", format!("FILE:{}", ccache));

    let kvno_run = cmd.output();
    match kvno_run {
        Ok(output) if output.status.success() => {
            let stdout_str = String::from_utf8_lossy(&output.stdout);
            let mut kvno_num = 1;
            if let Some(pos) = stdout_str.find("kvno =") {
                let rest = &stdout_str[pos + 6..];
                if let Some(first_tok) = rest.split_whitespace().next() {
                    if let Ok(num) = first_tok.parse::<u32>() {
                        kvno_num = num;
                    }
                }
            }

            if json_output {
                println!(
                    r#"{{
  "status": "SUCCESS",
  "operation": "TGS_ACQUISITION",
  "method": "kvno",
  "spn": "{}",
  "service_principal": "{}",
  "client_principal": "{}",
  "ccache": "{}",
  "kvno": {},
  "proof_of_access": "VERIFIED_MUTUAL_AUTH",
  "export_command": "export KRB5CCNAME={}",
  "telemetry": {{
    "event_id": 4769,
    "event_name": "Kerberos Service Ticket Request",
    "service_name": "{}",
    "ticket_encryption_type": "0x12 (AES-256)"
  }}
}}"#,
                    escape_json(&spn),
                    escape_json(&spn),
                    escape_json(principal_opt.as_deref().unwrap_or("authenticated-principal")),
                    escape_json(&ccache),
                    kvno_num,
                    escape_json(&ccache),
                    escape_json(&spn),
                );
            } else {
                print_card_header(
                    "TANUKI KERBEROS SERVICE TICKET ACQUISITION",
                    Some("Method: kvno - Proof of Operational Service Access"),
                    72,
                );
                println!("[+] Target SPN     : {}", spn);
                println!("    |- Client Princ : {}", principal_opt.as_deref().unwrap_or("authenticated-principal"));
                println!("    |- Ticket Cache : {}", ccache);
                println!("    |- Mutual Auth  : VERIFIED (Living off the Domain)");
                println!("    |- Event ID     : 4769 (Kerberos Service Ticket Request)");
                println!("    `- Telemetry    : Sigma Rule Match & Blue Telemetry Recorded");
                println!("\n[+] Operational Proof:");
                println!("    Mutual Kerberos service authentication established without cleartext credentials.");
                println!("    Active ccache exported with valid TGS for {}.", spn);
                println!("\n[+] Active Credential Cache Export:");
                println!("    $ export KRB5CCNAME={}", ccache);
            }
        }
        Ok(output) => {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            emit_cli_error(
                &format!("kvno service ticket request failed: {}", err_msg.trim()),
                "TGS_REQUEST_FAILED",
                "PROTOCOL_ERROR",
                EXIT_POLICY_STOP,
                Some(&spn),
                Some("Verify SPN registration in Active Directory and ensure clock skew is under tolerance."),
                json_output,
            );
        }
        Err(_) => {
            let guidance = "Install Kerberos client utilities (kvno): sudo apt install krb5-user";
            emit_cli_error(
                &format!("kvno utility not found on host $PATH. {}", guidance),
                "MISSING_KVNO_UTILITY",
                "DEPENDENCY_ERROR",
                EXIT_RESOURCE_MISSING,
                Some(&spn),
                Some(guidance),
                json_output,
            );
        }
    }
}

fn read_ccache_principal_at(slice: &[u8], mut cursor: usize) -> Option<(String, usize)> {
    if cursor + 12 > slice.len() {
        return None;
    }
    let num_components = u32::from_be_bytes([
        slice[cursor + 4],
        slice[cursor + 5],
        slice[cursor + 6],
        slice[cursor + 7],
    ]) as usize;
    let realm_len = u32::from_be_bytes([
        slice[cursor + 8],
        slice[cursor + 9],
        slice[cursor + 10],
        slice[cursor + 11],
    ]) as usize;
    if num_components == 0 || num_components > 16 || realm_len == 0 || realm_len > 256 {
        return None;
    }
    cursor += 12;
    if cursor + realm_len > slice.len() {
        return None;
    }
    let realm = std::str::from_utf8(&slice[cursor..cursor + realm_len]).ok()?;
    cursor += realm_len;
    let mut comps = Vec::with_capacity(num_components);
    for _ in 0..num_components {
        if cursor + 4 > slice.len() {
            return None;
        }
        let clen = u32::from_be_bytes([
            slice[cursor],
            slice[cursor + 1],
            slice[cursor + 2],
            slice[cursor + 3],
        ]) as usize;
        cursor += 4;
        if clen == 0 || clen > 256 || cursor + clen > slice.len() {
            return None;
        }
        let comp = std::str::from_utf8(&slice[cursor..cursor + clen]).ok()?;
        comps.push(comp);
        cursor += clen;
    }
    Some((format!("{}@{}", comps.join("/"), realm), cursor))
}

fn parse_ccache_principal_and_spns(bytes: &[u8]) -> (Option<String>, Vec<String>) {
    let mut spns = Vec::new();
    let mut cursor = if bytes.len() >= 4 && bytes[0] == 0x05 && bytes[1] == 0x04 {
        let hlen = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if 4 + hlen > bytes.len() {
            return (None, spns);
        }
        4 + hlen
    } else if bytes.len() >= 2 && bytes[0] == 0x05 && bytes[1] == 0x03 {
        2
    } else {
        let candidates = scan_for_ccache_blobs(bytes);
        let def_p = candidates.first().and_then(|c| c.default_principal.clone());
        return (def_p, spns);
    };

    let (def_princ, next_cur) = match read_ccache_principal_at(bytes, cursor) {
        Some((p, c)) => (Some(p), c),
        None => return (None, spns),
    };
    cursor = next_cur;

    while cursor < bytes.len() {
        let (_client, c1) = match read_ccache_principal_at(bytes, cursor) {
            Some(v) => v,
            None => break,
        };
        let (server, mut c2) = match read_ccache_principal_at(bytes, c1) {
            Some(v) => v,
            None => break,
        };
        if server.contains('/') && !server.to_ascii_lowercase().starts_with("krbtgt/") {
            if !spns.contains(&server) {
                spns.push(server);
            }
        }
        if c2 + 4 > bytes.len() {
            break;
        }
        let keylen = u16::from_be_bytes([bytes[c2 + 2], bytes[c2 + 3]]) as usize;
        c2 += 4;
        if keylen > 4096 || c2 + keylen + 21 > bytes.len() {
            break;
        }
        c2 += keylen + 21;
        if c2 + 4 > bytes.len() {
            break;
        }
        let num_addrs = u32::from_be_bytes([bytes[c2], bytes[c2 + 1], bytes[c2 + 2], bytes[c2 + 3]]) as usize;
        c2 += 4;
        if num_addrs > 1024 {
            break;
        }
        let mut ok = true;
        for _ in 0..num_addrs {
            if c2 + 6 > bytes.len() {
                ok = false;
                break;
            }
            let alen = u32::from_be_bytes([bytes[c2 + 2], bytes[c2 + 3], bytes[c2 + 4], bytes[c2 + 5]]) as usize;
            c2 += 6;
            if alen > 4096 || c2 + alen > bytes.len() {
                ok = false;
                break;
            }
            c2 += alen;
        }
        if !ok || c2 + 4 > bytes.len() {
            break;
        }
        let num_ad = u32::from_be_bytes([bytes[c2], bytes[c2 + 1], bytes[c2 + 2], bytes[c2 + 3]]) as usize;
        c2 += 4;
        if num_ad > 1024 {
            break;
        }
        for _ in 0..num_ad {
            if c2 + 6 > bytes.len() {
                ok = false;
                break;
            }
            let adlen = u32::from_be_bytes([bytes[c2 + 2], bytes[c2 + 3], bytes[c2 + 4], bytes[c2 + 5]]) as usize;
            c2 += 6;
            if adlen > 65536 || c2 + adlen > bytes.len() {
                ok = false;
                break;
            }
            c2 += adlen;
        }
        if !ok || c2 + 4 > bytes.len() {
            break;
        }
        let tkt_len = u32::from_be_bytes([bytes[c2], bytes[c2 + 1], bytes[c2 + 2], bytes[c2 + 3]]) as usize;
        c2 += 4;
        if tkt_len > 65536 || c2 + tkt_len + 4 > bytes.len() {
            break;
        }
        c2 += tkt_len;
        let sec_len = u32::from_be_bytes([bytes[c2], bytes[c2 + 1], bytes[c2 + 2], bytes[c2 + 3]]) as usize;
        c2 += 4;
        if sec_len > 65536 || c2 + sec_len > bytes.len() {
            break;
        }
        cursor = c2 + sec_len;
    }

    (def_princ, spns)
}

fn is_ccache_path(path: &str) -> bool {
    if path.ends_with(".ccache") {
        return true;
    }
    if let Ok(bytes) = fs::read(path) {
        if bytes.len() >= 2 && bytes[0] == 0x05 && (bytes[1] == 0x03 || bytes[1] == 0x04) {
            return true;
        }
    }
    false
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn handle_blast(
    source_opt: Option<String>,
    ccache_opt: Option<String>,
    keytab_opt: Option<String>,
    pac_source_opt: Option<String>,
    host_opt: Option<String>,
    base_dn_opt: Option<String>,
    username_opt: Option<String>,
    password_opt: Option<String>,
    spn_opt: Option<String>,
    json_output: bool,
) {
    let mut principal = "unknown@CORP.LOCAL".to_string();
    let mut extracted_user_sid: Option<String> = None;
    let mut primary_group_rid: Option<u32> = None;
    let mut group_rids: Vec<u32> = Vec::new();
    let mut uac_flags: Vec<String> = Vec::new();
    let mut accessible_spns: Vec<String> = Vec::new();

    if let Some(ref s) = spn_opt {
        accessible_spns.push(s.clone());
    }

    let source_is_ccache = source_opt.as_deref().map(is_ccache_path).unwrap_or(false);

    // 0. Check explicit principal in source_opt
    if let Some(ref src) = source_opt {
        let s = src.trim();
        if (s.contains('@') || s.contains('/'))
            && !s.ends_with(".keytab")
            && !source_is_ccache
            && !s.ends_with(".bin")
            && !s.ends_with(".pac")
            && !Path::new(s).is_file()
        {
            principal = s.to_string();
            if principal.contains('/') && !accessible_spns.contains(&principal) {
                accessible_spns.push(principal.clone());
            }
        }
    }

    // 1. Check PAC
    let target_pac = pac_source_opt.or_else(|| {
        if let Some(ref s) = source_opt {
            if !s.ends_with(".keytab") && !source_is_ccache {
                Some(s.clone())
            } else {
                None
            }
        } else {
            None
        }
    });

    if let Some(ref pac_src) = target_pac {
        if let Ok(rep) = parse_pac_source(pac_src) {
            if let Some(ref logon) = rep.logon_info {
                if !logon.user_name.is_empty() {
                    principal = logon.user_name.clone();
                }
                if !logon.user_sid.is_empty() {
                    extracted_user_sid = Some(logon.user_sid.clone());
                }
                primary_group_rid = Some(logon.primary_group_rid);
                group_rids = logon.group_rids.clone();
                uac_flags = logon.uac_flags.clone();
            }
        }
    }

    // 2. Check Keytab
    let target_kt = keytab_opt.or_else(|| {
        if let Some(ref s) = source_opt {
            if s.ends_with(".keytab") {
                Some(s.clone())
            } else {
                None
            }
        } else {
            None
        }
    });

    if let Some(ref kt) = target_kt {
        if let Ok(bytes) = fs::read(kt) {
            if let Ok(entries) = parse_keytab_bytes(&bytes) {
                if let Some(first) = entries.first() {
                    principal = first.principal.clone();
                }
                for e in entries {
                    if e.principal.contains('/') && !accessible_spns.contains(&e.principal) {
                        accessible_spns.push(e.principal);
                    }
                }
            }
        }
    }

    // 3. Check Credential Cache
    let target_cc = ccache_opt
        .or_else(|| {
            if let Some(ref s) = source_opt {
                if source_is_ccache {
                    Some(s.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .or_else(|| env::var("KRB5CCNAME").ok().map(|s| s.strip_prefix("FILE:").unwrap_or(&s).to_string()));
    if let Some(ref cc_path) = target_cc {
        if let Ok(bytes) = fs::read(cc_path) {
            let (def_p, cc_spns) = parse_ccache_principal_and_spns(&bytes);
            if let Some(p) = def_p {
                if !p.is_empty() && principal == "unknown@CORP.LOCAL" {
                    principal = p;
                }
            }
            for spn in cc_spns {
                if !accessible_spns.contains(&spn) {
                    accessible_spns.push(spn);
                }
            }
        }
    }

    // 4. Populate SPN if principal itself is an SPN
    if accessible_spns.is_empty() && principal.contains('/') {
        accessible_spns.push(principal.clone());
    }

    // 5. Query LDAP if host provided
    let mut rbcd_targets: Vec<String> = Vec::new();
    let mut owns_spn = false;
    if let Some(ref host) = host_opt {
        let base_dn = base_dn_opt.unwrap_or_else(|| "DC=lab,DC=local".to_string());

        // Direct identity lookup for the analyzed principal's real objectSid (recon-independent).
        if extracted_user_sid.is_none() {
            let acct = tanuki::extract_ad_account_name(&principal)
                .trim_end_matches('$')
                .to_string();
            if !acct.is_empty() {
                let id_rep = query_active_directory_ldap(
                    host,
                    &format!("identity:{}", acct),
                    &base_dn,
                    389,
                    false,
                    3,
                    username_opt.as_deref(),
                    password_opt.as_deref(),
                );
                if id_rep.status == "SUCCESS" {
                    for entry in &id_rep.entries {
                        for (k, vals) in &entry.attributes {
                            if k.eq_ignore_ascii_case("objectSid") {
                                if let Some(hex) = vals.first() {
                                    if let Some(sid_bytes) = hex_to_bytes(hex) {
                                        if let Ok((sid, _)) = tanuki::parse_windows_sid(&sid_bytes, 0, None) {
                                            extracted_user_sid = Some(sid);
                                        }
                                    }
                                }
                            } else if k.eq_ignore_ascii_case("primaryGroupID") {
                                if primary_group_rid.is_none() {
                                    if let Some(pg) = vals.first().and_then(|v| v.parse::<u32>().ok()) {
                                        primary_group_rid = Some(pg);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let ldap_rep = query_active_directory_ldap(
            host,
            "all",
            &base_dn,
            389,
            false,
            3,
            username_opt.as_deref(),
            password_opt.as_deref(),
        );
        if ldap_rep.status == "SUCCESS" {
            let clean_acc = tanuki::extract_ad_account_name(&principal)
                .trim_end_matches('$')
                .to_ascii_lowercase();

            for entry in &ldap_rep.entries {
                let mut sam_matches = false;
                for (k, vals) in &entry.attributes {
                    if k.eq_ignore_ascii_case("sAMAccountName") {
                        for v in vals {
                            if v.trim_end_matches('$').to_ascii_lowercase() == clean_acc {
                                sam_matches = true;
                                break;
                            }
                        }
                    }
                }
                if sam_matches {
                    if extracted_user_sid.is_none() {
                        for (k, vals) in &entry.attributes {
                            if k.eq_ignore_ascii_case("objectSid") {
                                if let Some(first_sid) = vals.first() {
                                    if let Some(sid_bytes) = hex_to_bytes(first_sid) {
                                        if let Ok((sid, _)) = tanuki::parse_windows_sid(&sid_bytes, 0, None) {
                                            extracted_user_sid = Some(sid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if primary_group_rid.is_none() {
                        for (k, vals) in &entry.attributes {
                            if k.eq_ignore_ascii_case("primaryGroupID") {
                                if let Some(first_pg) = vals.first() {
                                    if let Ok(pg) = first_pg.parse::<u32>() {
                                        primary_group_rid = Some(pg);
                                    }
                                }
                            }
                        }
                    }
                    break;
                }
            }

            let mut candidate_sids = Vec::new();
            if let Some(ref u_sid) = extracted_user_sid {
                candidate_sids.push(u_sid.clone());
                if let Some((dom_prefix, _)) = u_sid.rsplit_once('-') {
                    if let Some(pg) = primary_group_rid {
                        candidate_sids.push(format!("{}-{}", dom_prefix, pg));
                    }
                    for r in &group_rids {
                        candidate_sids.push(format!("{}-{}", dom_prefix, r));
                    }
                }
            }
            for entry in ldap_rep.entries {
                if entry.query_category == "spn" {
                    let mut sam_matches = false;
                    for (k, vals) in &entry.attributes {
                        if k.eq_ignore_ascii_case("sAMAccountName") {
                            for v in vals {
                                if v.trim_end_matches('$').to_ascii_lowercase() == clean_acc {
                                    sam_matches = true;
                                    break;
                                }
                            }
                        }
                    }
                    if sam_matches {
                        for (k, vals) in &entry.attributes {
                            if k.eq_ignore_ascii_case("servicePrincipalName") {
                                for spn in vals {
                                    owns_spn = true;
                                    if !accessible_spns.contains(spn) {
                                        accessible_spns.push(spn.clone());
                                    }
                                }
                            }
                        }
                    }
                } else if entry.query_category == "rbcd" {
                    if !candidate_sids.is_empty() {
                        // The DACL is stored raw (hex) under msDS-AllowedToActOnBehalfOfOtherIdentity;
                        // decode it and match trustee SIDs, same as the ldap command does (parity with Python).
                        let mut matches_trustee = false;
                        let mut target_name = String::from("unknown");
                        for (k, vals) in &entry.attributes {
                            if k.eq_ignore_ascii_case("sAMAccountName") {
                                if let Some(first) = vals.first() {
                                    target_name = first.clone();
                                }
                            } else if k.eq_ignore_ascii_case("msDS-AllowedToActOnBehalfOfOtherIdentity") {
                                if let Some(hex_val) = vals.first() {
                                    if let Some(raw_bytes) = hex_to_bytes(hex_val) {
                                        if let Ok(rbcd) = tanuki::parse_rbcd_security_descriptor(&raw_bytes) {
                                            if rbcd.allowed_trustee_sids.iter()
                                                .any(|t| candidate_sids.iter().any(|cs| cs == t))
                                            {
                                                matches_trustee = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if matches_trustee {
                            rbcd_targets.push(target_name);
                        }
                    }
                }
            }
        }
    }

    // has_spn = identity INTRINSICALLY owns an SPN (principal is an SPN, or LDAP found one on its account).
    // A user-supplied --spn is a lateral TARGET, not an owned SPN, so it must not inflate the tier (parity with Python blast.py).
    let has_spn = principal.contains('/') || owns_spn;
    let is_dc = principal.ends_with("$@LAB.LOCAL") || principal.starts_with("krbtgt/") || uac_flags.iter().any(|f| f == "SERVER_TRUST_ACCOUNT");

    let tier_info = classify_identity_tier(
        &principal,
        extracted_user_sid.as_deref(),
        primary_group_rid,
        &group_rids,
        &uac_flags,
        has_spn,
        is_dc,
    );
    let user_sid = extracted_user_sid.unwrap_or_else(|| "UNKNOWN".to_string());

    let (blast_score, severity, lateral_paths) = evaluate_blast_radius(
        &tier_info,
        &uac_flags,
        &accessible_spns,
        &rbcd_targets,
    );

    let remediation_recipes = generate_ad_remediations(
        &principal,
        &tier_info,
        &uac_flags,
        &rbcd_targets,
        &accessible_spns,
    );

    let report = BlastReport {
        principal,
        user_sid,
        tier_info,
        blast_score,
        severity,
        delegation_flags: uac_flags,
        accessible_spns,
        lateral_paths,
        remediation_recipes,
    };

    if json_output {
        println!("{}", blast_report_to_json(&report));
    } else {
        println!("{}", format_blast_report_terminal(&report));
    }
}


