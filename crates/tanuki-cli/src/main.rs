use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use tanuki::{
    candidates_to_json, entries_to_json, errors_to_json, find_error_resolution, ladder_to_json,
    parse_keytab_bytes, save_candidates, scan_for_ccache_blobs, DECISION_LADDER, ERROR_DICTIONARY,
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

OPTIONS:
    -f, --file <PATH>   Target database or keytab file
    -o, --out <DIR>     Output directory for extracted caches (default: ./extracted_ccache)
    --json              Output structured JSON for agent and pipeline consumption
    -h, --help          Print help information
    -V, --version       Print version information"#
    );
}

fn main() {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    if raw_args.is_empty() {
        print_usage();
        process::exit(1);
    }

    let mut global_json = false;
    let mut explicit_command: Option<String> = None;
    let mut positional_args: Vec<String> = Vec::new();
    let mut file_opt: Option<String> = None;
    let mut out_opt: Option<String> = None;

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
            cmd if explicit_command.is_none()
                && matches!(cmd, "keytab" | "kcm" | "triage" | "ladder") =>
            {
                explicit_command = Some(cmd.to_string());
            }
            other if !other.starts_with('-') => {
                positional_args.push(other.to_string());
            }
            other => {
                eprintln!("Unknown option: {}", other);
                print_usage();
                process::exit(1);
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
        "help" => {
            print_usage();
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            print_usage();
            process::exit(1);
        }
    }
}

fn handle_keytab(file_path: Option<String>, json_output: bool) {
    let path = match file_path {
        Some(p) => p,
        None => {
            eprintln!("Error: Keytab path required. Example: tanuki keytab /etc/krb5.keytab");
            process::exit(1);
        }
    };

    let data = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("Error reading keytab at '{}': {}", path, err);
            process::exit(1);
        }
    };

    let entries = match parse_keytab_bytes(&data) {
        Ok(list) => list,
        Err(err) => {
            eprintln!("Error parsing keytab: {}", err);
            process::exit(1);
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
                eprintln!("Error reading database '{}': {}", path, err);
                process::exit(1);
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
        println!("    {}\n", rung.description);
    }
    println!("Command Output Standard:");
    println!("    [TARGET] -> [PREREQUISITE] -> [TACTICAL COMMAND] -> [EXPECTED ARTIFACT] -> [OPSEC RATIONALE]");
    println!("========================================================================");
}
