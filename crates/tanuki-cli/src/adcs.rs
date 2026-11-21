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

use crate::nhi::jwt::{parse_json, JsonValue};

fn json_get_str(obj: &JsonValue, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn json_get_u32(obj: &JsonValue, key: &str) -> Option<u32> {
    let val = obj.get(key)?;
    if let Some(i) = val.as_i64() {
        return u32::try_from(i).ok();
    }
    if let Some(s) = val.as_str() {
        let clean = s.trim();
        if let Some(hex_part) = clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
            return u32::from_str_radix(hex_part, 16).ok();
        }
        return clean.parse::<u32>().ok();
    }
    None
}

fn json_get_bool(obj: &JsonValue, key: &str) -> Option<bool> {
    obj.get(key).and_then(|v| v.as_bool())
}

fn json_get_str_array(obj: &JsonValue, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                out.push(s.to_string());
            }
        }
    } else if let Some(s) = obj.get(key).and_then(|v| v.as_str()) {
        out.push(s.to_string());
    }
    out
}

fn extract_json_objects<'a>(root: &'a JsonValue) -> Vec<&'a JsonValue> {
    match root {
        JsonValue::Array(items) => items
            .iter()
            .filter(|v| matches!(v, JsonValue::Object(_)))
            .collect(),
        JsonValue::Object(_) => {
            if let Some(arr) = root.get("templates").and_then(|v| v.as_array()) {
                arr.iter()
                    .filter(|v| matches!(v, JsonValue::Object(_)))
                    .collect()
            } else {
                vec![root]
            }
        }
        _ => Vec::new(),
    }
}

fn encode_oid_to_der_bytes(oid_str: &str) -> Vec<u8> {
    let parts: Vec<u64> = oid_str
        .trim()
        .split('.')
        .filter(|s| !s.is_empty())
        .filter_map(|p| p.parse::<u64>().ok())
        .collect();
    if parts.len() < 2 {
        return Vec::new();
    }
    let mut body = Vec::new();
    body.push((parts[0] * 40 + parts[1]) as u8);
    for &val in &parts[2..] {
        if val == 0 {
            body.push(0);
        } else {
            let mut vlq = Vec::new();
            let mut v = val;
            while v > 0 {
                vlq.push((v & 0x7F) as u8);
                v >>= 7;
            }
            vlq.reverse();
            let vlen = vlq.len();
            for item in vlq.iter_mut().take(vlen - 1) {
                *item |= 0x80;
            }
            body.extend_from_slice(&vlq);
        }
    }
    let mut out = vec![0x06, body.len() as u8];
    out.extend_from_slice(&body);
    out
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

    let has_client_auth = ekus.iter().any(|raw_e| {
        let e = raw_e.trim();
        let low = e.to_lowercase();
        e == OID_CLIENT_AUTH
            || e == OID_SMARTCARD_LOGON
            || e == OID_PKINIT_CLIENT_AUTH
            || low.contains("client auth")
            || low.contains("smart card")
            || low.contains("pkinit")
    });
    let has_any_purpose = ekus.is_empty()
        || ekus.iter().any(|raw_e| {
            let e = raw_e.trim();
            e == OID_ANY_PURPOSE || e.to_lowercase().contains("any purpose")
        });
    let has_enrollment_agent = ekus.iter().any(|raw_e| {
        let e = raw_e.trim();
        let low = e.to_lowercase();
        e == OID_CERT_REQUEST_AGENT || low.contains("enrollment agent") || low.contains("request agent")
    });

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
    pki_writers: &[String],
    vuln_pki_acl: bool,
    http_enrollment: bool,
    epa: bool,
    https: bool,
    cert_mapping: Option<u32>,
    rpc_no_privacy: bool,
) -> Vec<AdcsFinding> {
    let mut findings = Vec::new();

    // ESC5: Vulnerable PKI Object or Container ACL Permissions
    if !pki_writers.is_empty() || vuln_pki_acl {
        let writers_str = if pki_writers.is_empty() {
            "low-privileged principals".to_string()
        } else {
            pki_writers.join(", ")
        };
        findings.push(AdcsFinding {
            vector: "ESC5".to_string(),
            severity: "CRITICAL".to_string(),
            template: ca_name.to_string(),
            title: "Vulnerable PKI Object or Container ACL Permissions".to_string(),
            description: format!("PKI architecture or CA object '{}' grants write/modify ACL permissions on PKI containers to {}.", ca_name, writers_str),
            remediation: "Restrict write/owner permissions on CN=Public Key Services and CA objects to Enterprise/Domain Admins.".to_string(),
        });
    }

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

fn scan_der_cert_for_client_auth(der_bytes: &[u8]) -> bool {
    let oids = [OID_CLIENT_AUTH, OID_SMARTCARD_LOGON, OID_PKINIT_CLIENT_AUTH, OID_ANY_PURPOSE];
    for oid in &oids {
        let der_pat = encode_oid_to_der_bytes(oid);
        if !der_pat.is_empty() && der_bytes.windows(der_pat.len()).any(|w| w == der_pat.as_slice()) {
            return true;
        }
        if der_pat.len() > 2 && der_bytes.windows(der_pat.len() - 2).any(|w| w == &der_pat[2..]) {
            return true;
        }
        let ascii_bytes = oid.as_bytes();
        if der_bytes.windows(ascii_bytes.len()).any(|w| w == ascii_bytes) {
            return true;
        }
    }
    false
}

pub fn scan_adcs_source(source: &str) -> Result<AdcsReport, String> {
    let p = Path::new(source);
    if let Ok(meta) = fs::symlink_metadata(p) {
        if meta.file_type().is_symlink() {
            return Err(format!("Refusing to read symbolic link: {}", source));
        }
    }
    if !p.exists() {
        return Err(format!("AD CS source file not found: {}", source));
    }

    let raw_bytes = fs::read(p).map_err(|e| format!("Failed to read file '{}': {}", source, e))?;
    if raw_bytes.len() > 10 * 1024 * 1024 {
        return Err("AD CS source file exceeds 10MB safety limit".to_string());
    }

    let mut all_findings = Vec::new();
    let mut scanned_count = 0;

    // Check raw binary DER certificate first
    if raw_bytes.len() >= 4 && raw_bytes[0] == 0x30 && (raw_bytes[1] == 0x82 || raw_bytes[1] == 0x81) {
        scanned_count = 1;
        if scan_der_cert_for_client_auth(&raw_bytes) {
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
        let content = String::from_utf8_lossy(&raw_bytes);
        if content.contains("-----BEGIN CERTIFICATE-----") {
            scanned_count = 1;
            let mut has_client = false;
            if let (Some(start), Some(end)) = (
                content.find("-----BEGIN CERTIFICATE-----"),
                content.find("-----END CERTIFICATE-----"),
            ) {
                let b64_body = &content[start + 27..end];
                if let Ok(der_bytes) = crate::nhi::b64url_decode(b64_body) {
                    if scan_der_cert_for_client_auth(&der_bytes) {
                        has_client = true;
                    }
                }
            }
            if !has_client {
                let oids = [OID_CLIENT_AUTH, OID_SMARTCARD_LOGON, OID_PKINIT_CLIENT_AUTH, OID_ANY_PURPOSE];
                for oid in &oids {
                    if content.contains(oid) {
                        has_client = true;
                        break;
                    }
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
        } else if let Ok(root_json) = parse_json(&content) {
            let objects = extract_json_objects(&root_json);
            if !objects.is_empty() {
                for obj in objects {
                    let editf = json_get_bool(obj, "EDITF_ATTRIBUTESUBJECTALTNAME2")
                        .or_else(|| json_get_bool(obj, "editf_san2"))
                        .unwrap_or(false);
                    let http_en = json_get_bool(obj, "http_enrollment_enabled").unwrap_or(false);
                    let rpc_no_priv = json_get_bool(obj, "rpc_enrollment_without_packet_privacy").unwrap_or(false);
                    let cert_map = json_get_u32(obj, "CertificateMappingMethods");
                    let low_mgrs = json_get_str_array(obj, "low_privileged_ca_managers");
                    let mut pki_writers = json_get_str_array(obj, "low_privileged_pki_writers");
                    if pki_writers.is_empty() {
                        pki_writers = json_get_str_array(obj, "low_privileged_ca_writers");
                    }
                    let vuln_pki_acl = json_get_bool(obj, "vulnerable_pki_acl").unwrap_or(false);
                    let has_ca_keys = editf
                        || http_en
                        || rpc_no_priv
                        || cert_map.is_some()
                        || !low_mgrs.is_empty()
                        || !pki_writers.is_empty()
                        || vuln_pki_acl
                        || json_get_str(obj, "ca_name").is_some();

                    let has_template_keys = obj.get("msPKI-Certificate-Name-Flag").is_some()
                        || obj.get("msPKI-Enrollment-Flag").is_some()
                        || obj.get("pKIExtendedKeyUsage").is_some()
                        || obj.get("name_flags").is_some()
                        || obj.get("enrollment_flags").is_some();

                    if has_ca_keys && !has_template_keys {
                        let ca_name = json_get_str(obj, "ca_name").unwrap_or_else(|| "Enterprise-CA".to_string());
                        let epa = json_get_bool(obj, "extended_protection_enabled").unwrap_or(false);
                        let https = json_get_bool(obj, "https_enforced").unwrap_or(false);
                        let ca_f = evaluate_ca(&ca_name, editf, &low_mgrs, &pki_writers, vuln_pki_acl, http_en, epa, https, cert_map, rpc_no_priv);
                        all_findings.extend(ca_f);
                    } else {
                        scanned_count += 1;
                        let name = json_get_str(obj, "cn")
                            .or_else(|| json_get_str(obj, "displayName"))
                            .or_else(|| json_get_str(obj, "name"))
                            .or_else(|| json_get_str(obj, "template_name"))
                            .or_else(|| json_get_str(obj, "TemplateName"))
                            .unwrap_or_else(|| format!("Template-{}", scanned_count));
                        let name_flags = json_get_u32(obj, "msPKI-Certificate-Name-Flag")
                            .or_else(|| json_get_u32(obj, "name_flags"))
                            .unwrap_or(0);
                        let enroll_flags = json_get_u32(obj, "msPKI-Enrollment-Flag")
                            .or_else(|| json_get_u32(obj, "enrollment_flags"))
                            .unwrap_or(0);
                        let ra_sigs = json_get_u32(obj, "msPKI-RA-Signature")
                            .or_else(|| json_get_u32(obj, "authorized_signatures"))
                            .or_else(|| json_get_u32(obj, "ra_signatures"))
                            .unwrap_or(0);
                        let ekus = json_get_str_array(obj, "pKIExtendedKeyUsage");
                        let writers = json_get_str_array(obj, "low_privileged_writers");
                        let f = evaluate_template(&name, name_flags, enroll_flags, ra_sigs, &ekus, &writers);
                        all_findings.extend(f);
                        if has_ca_keys {
                            let ca_name = json_get_str(obj, "ca_name").unwrap_or_else(|| "Enterprise-CA".to_string());
                            let epa = json_get_bool(obj, "extended_protection_enabled").unwrap_or(false);
                            let https = json_get_bool(obj, "https_enforced").unwrap_or(false);
                            let ca_f = evaluate_ca(&ca_name, editf, &low_mgrs, &pki_writers, vuln_pki_acl, http_en, epa, https, cert_map, rpc_no_priv);
                            all_findings.extend(ca_f);
                        }
                    }
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
