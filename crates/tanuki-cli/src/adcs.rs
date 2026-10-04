use crate::util::escape_json;
use std::fs;
use std::path::Path;

pub const OID_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
pub const OID_SMARTCARD_LOGON: &str = "1.3.6.1.4.1.311.20.2.2";
pub const OID_PKINIT_CLIENT_AUTH: &str = "1.3.6.1.5.2.3.4";
pub const OID_ANY_PURPOSE: &str = "2.5.29.37.0";
pub const OID_CERT_REQUEST_AGENT: &str = "1.3.6.1.4.1.311.20.2.1";

pub const CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT: u32 = 0x00000001;
pub const CT_FLAG_PEND_ALL_REQUESTS: u32 = 0x00000002;
pub const CT_FLAG_NO_SECURITY_EXTENSION: u32 = 0x00080000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdcsFinding {
    pub vector: String,
    pub severity: String,
    pub template: String,
    pub title: String,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdcsReport {
    pub status: String,
    pub scanned_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub findings: Vec<AdcsFinding>,
}

impl AdcsReport {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"status\": \"{}\",\n", escape_json(&self.status)));
        out.push_str(&format!("  \"scanned_count\": {},\n", self.scanned_count));
        out.push_str("  \"summary\": {\n");
        out.push_str(&format!("    \"critical\": {},\n", self.critical_count));
        out.push_str(&format!("    \"high\": {},\n", self.high_count));
        out.push_str(&format!("    \"medium\": {},\n", self.medium_count));
        out.push_str(&format!("    \"total\": {}\n", self.findings.len()));
        out.push_str("  },\n");
        out.push_str("  \"findings\": [\n");
        for (i, f) in self.findings.iter().enumerate() {
            out.push_str("    {\n");
            out.push_str(&format!("      \"vector\": \"{}\",\n", escape_json(&f.vector)));
            out.push_str(&format!("      \"severity\": \"{}\",\n", escape_json(&f.severity)));
            out.push_str(&format!("      \"template\": \"{}\",\n", escape_json(&f.template)));
            out.push_str(&format!("      \"title\": \"{}\",\n", escape_json(&f.title)));
            out.push_str(&format!("      \"description\": \"{}\",\n", escape_json(&f.description)));
            out.push_str(&format!("      \"remediation\": \"{}\"\n", escape_json(&f.remediation)));
            out.push_str("    }");
            if i + 1 < self.findings.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ]\n}");
        out
    }

    pub fn format_terminal(&self) -> String {
        let mut out = String::new();
        out.push_str("[TANUKI AD CS TEMPLATE & CERTIFICATE SCANNER]\n");
        out.push_str(&format!(" ESC1 through ESC11 Offline Diagnostic · {} Misconfigurations Detected\n\n", self.findings.len()));

        if self.findings.is_empty() {
            out.push_str("[*] Scanned Templates: No ESC1-ESC11 misconfigurations detected. All templates secure.\n");
        } else {
            out.push_str(&format!(
                "[+] Total Vulnerabilities Detected: {} (Critical: {}, High: {}, Medium: {})\n\n",
                self.findings.len(),
                self.critical_count,
                self.high_count,
                self.medium_count
            ));
            for (idx, f) in self.findings.iter().enumerate() {
                out.push_str(&format!("[{}] {} · {} [{}]\n", f.severity, f.vector, f.title, f.template));
                out.push_str(&format!("    ├─ Description : {}\n", f.description));
                out.push_str(&format!("    ╰─ Remediation : {}\n", f.remediation));
                if idx + 1 < self.findings.len() {
                    out.push('\n');
                }
            }
        }
        out
    }
}

fn extract_json_str(obj_str: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let pos = obj_str.find(&pattern)?;
    let colon_pos = obj_str[pos + pattern.len()..].find(':')? + pos + pattern.len();
    let quote_start = obj_str[colon_pos + 1..].find('"')? + colon_pos + 1;
    let quote_end = obj_str[quote_start + 1..].find('"')? + quote_start + 1;
    Some(obj_str[quote_start + 1..quote_end].to_string())
}

fn extract_json_u32(obj_str: &str, key: &str) -> Option<u32> {
    let pattern = format!("\"{}\"", key);
    let pos = obj_str.find(&pattern)?;
    let colon_pos = obj_str[pos + pattern.len()..].find(':')? + pos + pattern.len();
    let slice = obj_str[colon_pos + 1..].trim_start();
    let num_str: String = slice.chars().take_while(|c| c.is_ascii_digit()).collect();
    num_str.parse::<u32>().ok()
}

fn extract_json_bool(obj_str: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{}\"", key);
    let pos = obj_str.find(&pattern)?;
    let colon_pos = obj_str[pos + pattern.len()..].find(':')? + pos + pattern.len();
    let slice = obj_str[colon_pos + 1..].trim_start();
    if slice.starts_with("true") {
        Some(true)
    } else if slice.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn extract_json_str_array(obj_str: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let pattern = format!("\"{}\"", key);
    if let Some(pos) = obj_str.find(&pattern) {
        if let Some(colon_pos) = obj_str[pos + pattern.len()..].find(':') {
            let start = pos + pattern.len() + colon_pos;
            if let Some(bracket_start) = obj_str[start..].find('[') {
                if let Some(bracket_end) = obj_str[start + bracket_start..].find(']') {
                    let array_content = &obj_str[start + bracket_start + 1..start + bracket_start + bracket_end];
                    let mut in_str = false;
                    let mut cur = String::new();
                    for c in array_content.chars() {
                        if c == '"' {
                            if in_str {
                                out.push(cur.clone());
                                cur.clear();
                                in_str = false;
                            } else {
                                in_str = true;
                            }
                        } else if in_str {
                            cur.push(c);
                        }
                    }
                }
            }
        }
    }
    out
}

fn split_json_objects(text: &str) -> Vec<&str> {
    let mut objects = Vec::new();
    let mut depth = 0;
    let mut start_idx = None;
    let mut in_string = false;
    let mut escape = false;

    for (idx, ch) in text.char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if ch == '\\' {
                escape = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else {
            match ch {
                '"' => in_string = true,
                '{' => {
                    if depth == 0 {
                        start_idx = Some(idx);
                    }
                    depth += 1;
                }
                '}' => {
                    if depth > 0 {
                        depth -= 1;
                        if depth == 0 {
                            if let Some(s) = start_idx {
                                objects.push(&text[s..=idx]);
                                start_idx = None;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    objects
}

pub fn evaluate_template(
    name: &str,
    name_flags: u32,
    enrollment_flags: u32,
    ra_signatures: u32,
    ekus: &[String],
    low_priv_writers: &[String],
) -> Vec<AdcsFinding> {
    let mut findings = Vec::new();

    let enrollee_supplies_subject = (name_flags & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) != 0;
    let requires_manager_approval = (enrollment_flags & CT_FLAG_PEND_ALL_REQUESTS) != 0;

    let has_client_auth = ekus.iter().any(|e| {
        e == OID_CLIENT_AUTH
            || e == OID_SMARTCARD_LOGON
            || e == OID_PKINIT_CLIENT_AUTH
            || e.to_lowercase().contains("client auth")
    });
    let has_any_purpose = ekus.is_empty() || ekus.iter().any(|e| e == OID_ANY_PURPOSE || e.to_lowercase().contains("any purpose"));
    let has_enrollment_agent = ekus.iter().any(|e| e == OID_CERT_REQUEST_AGENT || e.to_lowercase().contains("enrollment agent"));

    // ESC1
    if enrollee_supplies_subject && (has_client_auth || has_any_purpose) && !requires_manager_approval && ra_signatures == 0 {
        findings.push(AdcsFinding {
            vector: "ESC1".to_string(),
            severity: "CRITICAL".to_string(),
            template: name.to_string(),
            title: "Enrollee Supplies Subject with Client Authentication".to_string(),
            description: format!("Template '{}' allows enrollee to supply arbitrary SANs with Client Auth without approval.", name),
            remediation: "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT or require manager approval.".to_string(),
        });
    }

    // ESC2
    if has_any_purpose && !requires_manager_approval && ra_signatures == 0 {
        findings.push(AdcsFinding {
            vector: "ESC2".to_string(),
            severity: "HIGH".to_string(),
            template: name.to_string(),
            title: "Any Purpose EKU or Subordinate CA Capabilities".to_string(),
            description: format!("Template '{}' contains Any Purpose EKU without approval requirements.", name),
            remediation: "Constrain EKU and enforce issuance requirements.".to_string(),
        });
    }

    // ESC3
    if has_enrollment_agent && !requires_manager_approval && ra_signatures == 0 {
        findings.push(AdcsFinding {
            vector: "ESC3".to_string(),
            severity: "HIGH".to_string(),
            template: name.to_string(),
            title: "Certificate Request Agent EKU (Enrollment Agent)".to_string(),
            description: format!("Template '{}' grants enrollment agent rights to request certificates on behalf of others.", name),
            remediation: "Restrict enrollment permissions or require authorized signatures.".to_string(),
        });
    }

    // ESC4
    if !low_priv_writers.is_empty() {
        findings.push(AdcsFinding {
            vector: "ESC4".to_string(),
            severity: "CRITICAL".to_string(),
            template: name.to_string(),
            title: "Vulnerable Template ACL Write Permissions".to_string(),
            description: format!("Template '{}' grants write permissions to low-privileged principals: {}.", name, low_priv_writers.join(", ")),
            remediation: "Remove write permissions from non-administrative domain security principals.".to_string(),
        });
    }

    // ESC9
    if (enrollment_flags & CT_FLAG_NO_SECURITY_EXTENSION) != 0 {
        findings.push(AdcsFinding {
            vector: "ESC9".to_string(),
            severity: "HIGH".to_string(),
            template: name.to_string(),
            title: "CT_FLAG_NO_SECURITY_EXTENSION Enabled (No objectSid Extension)".to_string(),
            description: format!("Template '{}' omits the objectSid extension, exposing domain to UPN spoofing.", name),
            remediation: "Unset CT_FLAG_NO_SECURITY_EXTENSION in msPKI-Enrollment-Flag.".to_string(),
        });
    }

    findings
}

pub fn evaluate_ca(
    ca_name: &str,
    editf_san2: bool,
    low_priv_ca_managers: &[String],
    http_enrollment: bool,
    epa: bool,
    https: bool,
    cert_mapping: Option<u32>,
    rpc_no_privacy: bool,
) -> Vec<AdcsFinding> {
    let mut findings = Vec::new();

    if editf_san2 {
        findings.push(AdcsFinding {
            vector: "ESC6".to_string(),
            severity: "CRITICAL".to_string(),
            template: ca_name.to_string(),
            title: "CA EDITF_ATTRIBUTESUBJECTALTNAME2 Flag Enabled".to_string(),
            description: format!("Certificate Authority '{}' allows arbitrary SANs on all templates.", ca_name),
            remediation: "certutil -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2".to_string(),
        });
    }

    if !low_priv_ca_managers.is_empty() {
        findings.push(AdcsFinding {
            vector: "ESC7".to_string(),
            severity: "HIGH".to_string(),
            template: ca_name.to_string(),
            title: "Vulnerable CA Administrative Permissions".to_string(),
            description: format!("CA '{}' grants administrative permissions to low-privileged users: {}.", ca_name, low_priv_ca_managers.join(", ")),
            remediation: "Restrict CA security permissions to Enterprise Admins only.".to_string(),
        });
    }

    if http_enrollment && (!epa || !https) {
        findings.push(AdcsFinding {
            vector: "ESC8".to_string(),
            severity: "HIGH".to_string(),
            template: ca_name.to_string(),
            title: "AD CS HTTP Web Enrollment Vulnerable to NTLM Relay".to_string(),
            description: format!("CA '{}' web enrollment does not enforce EPA with HTTPS channel binding.", ca_name),
            remediation: "Enable EPA in IIS for CertSrv and enforce HTTPS-only binding.".to_string(),
        });
    }

    if let Some(m) = cert_mapping {
        if m == 0x4 || m == 0x2 {
            findings.push(AdcsFinding {
                vector: "ESC10".to_string(),
                severity: "HIGH".to_string(),
                template: ca_name.to_string(),
                title: "Weak DC Certificate Mapping Methods (UPN vs objectSid)".to_string(),
                description: format!("Domain Controller certificate mapping registry key is set to 0x{:x}.", m),
                remediation: "Set CertificateMappingMethods to 0x18.".to_string(),
            });
        }
    }

    if rpc_no_privacy {
        findings.push(AdcsFinding {
            vector: "ESC11".to_string(),
            severity: "HIGH".to_string(),
            template: ca_name.to_string(),
            title: "Relaying NTLM to RPC Enrollment Endpoint".to_string(),
            description: format!("RPC enrollment interface on '{}' does not enforce packet privacy.", ca_name),
            remediation: "Enforce RPC packet privacy (RPC_C_AUTHN_LEVEL_PKT_PRIVACY).".to_string(),
        });
    }

    findings
}

pub fn scan_adcs_source(source: &str) -> Result<AdcsReport, String> {
    let p = Path::new(source);
    if !p.exists() {
        return Err(format!("AD CS source file not found: {}", source));
    }

    let content = fs::read_to_string(p).map_err(|e| format!("Failed to read file '{}': {}", source, e))?;

    let mut all_findings = Vec::new();
    let mut scanned_count = 0;

    if content.contains("-----BEGIN CERTIFICATE-----") {
        scanned_count = 1;
        let mut has_client = false;
        let oids = [OID_CLIENT_AUTH, OID_SMARTCARD_LOGON, OID_PKINIT_CLIENT_AUTH];
        for oid in &oids {
            if content.contains(oid) {
                has_client = true;
                break;
            }
        }
        if has_client {
            all_findings.push(AdcsFinding {
                vector: "CERT_CLIENT_AUTH".to_string(),
                severity: "INFO".to_string(),
                template: "X509Certificate".to_string(),
                title: "Certificate Contains Client Authentication EKU".to_string(),
                description: "X.509 certificate specifies Client Authentication EKUs.".to_string(),
                remediation: "Review certificate issuance and usage constraints.".to_string(),
            });
        }
    } else {
        let objects = split_json_objects(&content);
        if !objects.is_empty() {
            for obj in objects {
                let editf = extract_json_bool(obj, "EDITF_ATTRIBUTESUBJECTALTNAME2")
                    .or_else(|| extract_json_bool(obj, "editf_san2"))
                    .unwrap_or(false);
                let http_en = extract_json_bool(obj, "http_enrollment_enabled").unwrap_or(false);

                if editf || http_en {
                    let ca_name = extract_json_str(obj, "ca_name").unwrap_or_else(|| "Enterprise-CA".to_string());
                    let epa = extract_json_bool(obj, "extended_protection_enabled").unwrap_or(false);
                    let https = extract_json_bool(obj, "https_enforced").unwrap_or(false);
                    let rpc_no_priv = extract_json_bool(obj, "rpc_enrollment_without_packet_privacy").unwrap_or(false);
                    let cert_map = extract_json_u32(obj, "CertificateMappingMethods");
                    let low_mgrs = extract_json_str_array(obj, "low_privileged_ca_managers");
                    let ca_f = evaluate_ca(&ca_name, editf, &low_mgrs, http_en, epa, https, cert_map, rpc_no_priv);
                    all_findings.extend(ca_f);
                } else {
                    scanned_count += 1;
                    let name = extract_json_str(obj, "name")
                        .or_else(|| extract_json_str(obj, "template_name"))
                        .or_else(|| extract_json_str(obj, "TemplateName"))
                        .unwrap_or_else(|| format!("Template-{}", scanned_count));
                    let name_flags = extract_json_u32(obj, "msPKI-Certificate-Name-Flag")
                        .or_else(|| extract_json_u32(obj, "name_flags"))
                        .unwrap_or(0);
                    let enroll_flags = extract_json_u32(obj, "msPKI-Enrollment-Flag")
                        .or_else(|| extract_json_u32(obj, "enrollment_flags"))
                        .unwrap_or(0);
                    let ra_sigs = extract_json_u32(obj, "msPKI-RA-Signature")
                        .or_else(|| extract_json_u32(obj, "authorized_signatures"))
                        .or_else(|| extract_json_u32(obj, "ra_signatures"))
                        .unwrap_or(0);
                    let ekus = extract_json_str_array(obj, "pKIExtendedKeyUsage");
                    let writers = extract_json_str_array(obj, "low_privileged_writers");
                    let f = evaluate_template(&name, name_flags, enroll_flags, ra_sigs, &ekus, &writers);
                    all_findings.extend(f);
                }
            }
        } else {
            scanned_count = 1;
            let mut name_flags = 0;
            if content.contains("CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT") {
                name_flags |= CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT;
            }
            let mut enroll_flags = 0;
            if content.contains("CT_FLAG_NO_SECURITY_EXTENSION") {
                enroll_flags |= CT_FLAG_NO_SECURITY_EXTENSION;
            }
            let mut ekus = Vec::new();
            if content.contains(OID_CLIENT_AUTH) || content.contains("Client Auth") {
                ekus.push(OID_CLIENT_AUTH.to_string());
            }
            let f = evaluate_template("Template-1", name_flags, enroll_flags, 0, &ekus, &[]);
            all_findings.extend(f);
        }
    }

    let critical_count = all_findings.iter().filter(|f| f.severity == "CRITICAL").count();
    let high_count = all_findings.iter().filter(|f| f.severity == "HIGH").count();
    let medium_count = all_findings.iter().filter(|f| f.severity == "MEDIUM").count();

    Ok(AdcsReport {
        status: "SUCCESS".to_string(),
        scanned_count,
        critical_count,
        high_count,
        medium_count,
        findings: all_findings,
    })
}
