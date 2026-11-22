use super::jwt::{parse_and_validate_jwt, parse_json, JsonValue};
use super::types::{TokenExchangeParams, TokenValidationReport};
use crate::util::escape_json;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

pub const RFC8693_TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

const SUPPORTED_TOKEN_TYPES: &[&str] = &[
    "urn:ietf:params:oauth:token-type:jwt",
    "urn:ietf:params:oauth:token-type:access_token",
    "urn:ietf:params:oauth:token-type:refresh_token",
    "urn:ietf:params:oauth:token-type:id_token",
    "urn:ietf:params:oauth:token-type:saml1",
    "urn:ietf:params:oauth:token-type:saml2",
];

pub fn validate_token_exchange(params: &TokenExchangeParams) -> TokenValidationReport {
    let grant = match &params.grant_type {
        Some(g) if !g.is_empty() => g.as_str(),
        _ => {
            return TokenValidationReport {
                valid: false,
                exchange_valid: false,
                error: Some("invalid_request".to_string()),
                error_description: Some("Missing required parameter 'grant_type'".to_string()),
                parameters: params.clone(),
                security_warnings: vec![
                    "INVALID_REQUEST: Missing required parameter 'grant_type'".to_string()
                ],
                subject_token_report: None,
            };
        }
    };

    if grant != RFC8693_TOKEN_EXCHANGE_GRANT {
        return TokenValidationReport {
            valid: false,
            exchange_valid: false,
            error: Some("unsupported_grant_type".to_string()),
            error_description: Some(format!(
                "Unsupported grant_type '{}'. Expected '{}'",
                grant, RFC8693_TOKEN_EXCHANGE_GRANT
            )),
            parameters: params.clone(),
            security_warnings: vec![
                "UNSUPPORTED_GRANT_TYPE: Grant type is not RFC 8693 token exchange".to_string(),
            ],
            subject_token_report: None,
        };
    }

    let subject_token = match &params.subject_token {
        Some(st) if !st.is_empty() => st.as_str(),
        _ => {
            return TokenValidationReport {
                valid: false,
                exchange_valid: false,
                error: Some("invalid_request".to_string()),
                error_description: Some("Missing required parameter 'subject_token'".to_string()),
                parameters: params.clone(),
                security_warnings: vec![
                    "INVALID_REQUEST: Missing required parameter 'subject_token'".to_string(),
                ],
                subject_token_report: None,
            };
        }
    };

    let subject_token_type = match &params.subject_token_type {
        Some(stt) if !stt.is_empty() => stt.as_str(),
        _ => {
            return TokenValidationReport {
                valid: false,
                exchange_valid: false,
                error: Some("invalid_request".to_string()),
                error_description: Some(
                    "Missing required parameter 'subject_token_type'".to_string(),
                ),
                parameters: params.clone(),
                security_warnings: vec![
                    "INVALID_REQUEST: Missing required parameter 'subject_token_type'".to_string(),
                ],
                subject_token_report: None,
            };
        }
    };

    if !SUPPORTED_TOKEN_TYPES.contains(&subject_token_type) {
        return TokenValidationReport {
            valid: false,
            exchange_valid: false,
            error: Some("invalid_request".to_string()),
            error_description: Some(format!(
                "Unsupported subject_token_type '{}'",
                subject_token_type
            )),
            parameters: params.clone(),
            security_warnings: vec![format!(
                "INVALID_REQUEST: Unsupported subject_token_type '{}'",
                subject_token_type
            )],
            subject_token_report: None,
        };
    }

    if let Some(rtt) = &params.requested_token_type {
        if !SUPPORTED_TOKEN_TYPES.contains(&rtt.as_str()) {
            return TokenValidationReport {
                valid: false,
                exchange_valid: false,
                error: Some("invalid_request".to_string()),
                error_description: Some(format!("Unsupported requested_token_type '{}'", rtt)),
                parameters: params.clone(),
                security_warnings: vec![format!(
                    "INVALID_REQUEST: Unsupported requested_token_type '{}'",
                    rtt
                )],
                subject_token_report: None,
            };
        }
    }

    let mut security_warnings = Vec::new();
    if let Some(aud) = &params.audience {
        if aud == "*" {
            security_warnings
                .push("WILDCARD_AUDIENCE: Dangerous wildcard audience detected: '*'".to_string());
        } else if aud.contains('*') {
            security_warnings.push(format!(
                "WILDCARD_AUDIENCE: Wildcard pattern in exchange audience: '{}'",
                aud
            ));
        }
    }

    let mut subject_report = None;
    if subject_token_type == "urn:ietf:params:oauth:token-type:jwt" {
        match parse_and_validate_jwt(subject_token, None, None) {
            Ok(rep) => {
                for w in &rep.security_warnings {
                    if !security_warnings.contains(w) {
                        security_warnings.push(w.clone());
                    }
                }
                if rep.temporal.is_expired == Some(true) {
                    return TokenValidationReport {
                        valid: false,
                        exchange_valid: false,
                        error: Some("invalid_grant".to_string()),
                        error_description: Some(
                            "The provided subject_token has expired".to_string(),
                        ),
                        parameters: params.clone(),
                        security_warnings,
                        subject_token_report: Some(rep),
                    };
                }
                if !rep.valid {
                    return TokenValidationReport {
                        valid: false,
                        exchange_valid: false,
                        error: Some("invalid_grant".to_string()),
                        error_description: Some(
                            "The provided subject_token failed security policy validation"
                                .to_string(),
                        ),
                        parameters: params.clone(),
                        security_warnings,
                        subject_token_report: Some(rep),
                    };
                }
                subject_report = Some(rep);
            }
            Err(e) => {
                return TokenValidationReport {
                    valid: false,
                    exchange_valid: false,
                    error: Some("invalid_request".to_string()),
                    error_description: Some(format!("Failed to parse subject_token JWT: {}", e)),
                    parameters: params.clone(),
                    security_warnings: vec![format!(
                        "INVALID_REQUEST: Malformed subject_token JWT: {}",
                        e
                    )],
                    subject_token_report: None,
                };
            }
        }
    }

    TokenValidationReport {
        valid: true,
        exchange_valid: true,
        error: None,
        error_description: None,
        parameters: params.clone(),
        security_warnings,
        subject_token_report: subject_report,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveExchangeReport {
    pub status: String,
    pub http_status: Option<u16>,
    pub endpoint: String,
    pub access_token: Option<String>,
    pub issued_token_type: Option<String>,
    pub token_type: Option<String>,
    pub expires_in: Option<i64>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub raw_response_json: String,
}

impl LiveExchangeReport {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!(
            "  \"status\": \"{}\",\n",
            escape_json(&self.status)
        ));
        if let Some(code) = self.http_status {
            out.push_str(&format!("  \"http_status\": {},\n", code));
        }
        out.push_str(&format!(
            "  \"endpoint\": \"{}\"",
            escape_json(&self.endpoint)
        ));
        if self.status == "SUCCESS" {
            out.push_str(&format!(",\n  \"response\": {}", self.raw_response_json));
            match &self.access_token {
                Some(v) => out.push_str(&format!(",\n  \"access_token\": \"{}\"", escape_json(v))),
                None => out.push_str(",\n  \"access_token\": null"),
            }
            match &self.issued_token_type {
                Some(v) => out.push_str(&format!(
                    ",\n  \"issued_token_type\": \"{}\"",
                    escape_json(v)
                )),
                None => out.push_str(",\n  \"issued_token_type\": null"),
            }
            match &self.token_type {
                Some(v) => out.push_str(&format!(",\n  \"token_type\": \"{}\"", escape_json(v))),
                None => out.push_str(",\n  \"token_type\": null"),
            }
            match self.expires_in {
                Some(v) => out.push_str(&format!(",\n  \"expires_in\": {}", v)),
                None => out.push_str(",\n  \"expires_in\": null"),
            }
        } else {
            if let Some(ref e) = self.error {
                out.push_str(&format!(",\n  \"error\": \"{}\"", escape_json(e)));
            }
            if let Some(ref d) = self.error_description {
                out.push_str(&format!(
                    ",\n  \"error_description\": \"{}\"",
                    escape_json(d)
                ));
            }
            if !self.raw_response_json.is_empty() {
                out.push_str(&format!(",\n  \"response\": {}", self.raw_response_json));
            }
        }
        out.push_str("\n}");
        out
    }

    pub fn format_terminal(&self) -> String {
        let mut out = String::new();
        out.push_str("[TANUKI RFC 8693 LIVE TOKEN EXCHANGE]\n");
        out.push_str(&format!(
            " Endpoint: {} · Status: {}\n",
            self.endpoint, self.status
        ));
        if self.status == "SUCCESS" {
            out.push_str(&format!(
                "[+] HTTP Status       : {} OK\n",
                self.http_status.unwrap_or(200)
            ));
            out.push_str(&format!(
                "    ├─ Issued Token Type : {}\n",
                self.issued_token_type.as_deref().unwrap_or("N/A")
            ));
            out.push_str(&format!(
                "    ├─ Token Type        : {}\n",
                self.token_type.as_deref().unwrap_or("Bearer")
            ));
            match self.expires_in {
                Some(exp) => out.push_str(&format!("    ├─ Expires In        : {}s\n", exp)),
                None => out.push_str("    ├─ Expires In        : N/A\n"),
            }
            let tok = self.access_token.as_deref().unwrap_or("");
            let preview = if tok.len() > 24 {
                format!("{}...", &tok[..24])
            } else {
                tok.to_string()
            };
            out.push_str(&format!("    ╰─ Access Token      : {}", preview));
        } else {
            match self.http_status {
                Some(code) => out.push_str(&format!("[!] HTTP Status       : {}\n", code)),
                None => out.push_str("[!] HTTP Status       : N/A\n"),
            }
            out.push_str(&format!(
                "    ├─ Error Code        : {}\n",
                self.error.as_deref().unwrap_or("unknown")
            ));
            out.push_str(&format!(
                "    ╰─ Description       : {}",
                self.error_description.as_deref().unwrap_or("N/A")
            ));
        }
        out
    }
}

fn url_encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{:02X}", b);
        }
    }
    out
}

fn parse_http_url(url: &str) -> Result<(String, String, u16, String), String> {
    if url.is_empty() || url.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err("URL contains invalid control characters or is empty".to_string());
    }
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("Unsupported or disallowed URL scheme in '{}'", url))?;
    let scheme_low = scheme.to_ascii_lowercase();
    if scheme_low != "http" && scheme_low != "https" {
        return Err(format!(
            "Unsupported or disallowed URL scheme: '{}'",
            scheme
        ));
    }
    let split_idx = rest.find(['/', '?', '#']);
    let (authority, tail) = match split_idx {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let tail_no_frag = tail.split('#').next().unwrap_or("/");
    let path_part = if tail_no_frag.is_empty() {
        "/".to_string()
    } else if tail_no_frag.starts_with('/') {
        tail_no_frag.to_string()
    } else {
        format!("/{}", tail_no_frag)
    };
    if authority.is_empty() {
        return Err("URL is missing a target host".to_string());
    }
    if authority.contains('@') {
        return Err("URL userinfo credentials are not permitted in exchange endpoint".to_string());
    }
    let default_port = if scheme_low == "https" { 443 } else { 80 };
    let (host, port) = if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or_else(|| "Unclosed IPv6 bracket in URL".to_string())?;
        let h = &authority[1..close];
        let after = &authority[close + 1..];
        let p = if after.is_empty() {
            default_port
        } else if let Some(ps) = after.strip_prefix(':') {
            ps.parse::<u16>()
                .map_err(|_| "Invalid port in URL".to_string())?
        } else {
            return Err("Invalid host authority in URL".to_string());
        };
        (h.to_string(), p)
    } else if let Some((h, ps)) = authority.rsplit_once(':') {
        let p = ps
            .parse::<u16>()
            .map_err(|_| "Invalid port in URL".to_string())?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), default_port)
    };
    if host.is_empty() || port == 0 {
        return Err("URL is missing a valid target host or port".to_string());
    }
    Ok((scheme_low, host, port, path_part))
}

fn raw_http_request(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout_ms: u64,
) -> Result<(u16, String), String> {
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve {}:{} ({})", host, port, e))?;
    let addr = addrs
        .next()
        .ok_or_else(|| format!("No socket address resolved for {}:{}", host, port))?;
    let timeout = Duration::from_millis(timeout_ms);
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| format!("Connection to {}:{} failed: {}", host, port, e))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let host_hdr = if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    };
    let body_bytes = body.unwrap_or(&[]);
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        method,
        path,
        host_hdr,
        body_bytes.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    req.push_str("\r\n");

    let mut full_req = Vec::with_capacity(req.len() + body_bytes.len());
    full_req.extend_from_slice(req.as_bytes());
    full_req.extend_from_slice(body_bytes);

    stream
        .write_all(&full_req)
        .map_err(|e| format!("HTTP write failed: {}", e))?;
    let _ = stream.flush();

    let mut resp_buf = Vec::new();
    let mut chunk = [0u8; 8192];
    while resp_buf.len() < 1024 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => resp_buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if resp_buf.is_empty() {
                    return Err(format!("HTTP read timed out: {}", e));
                }
                break;
            }
            Err(e) => return Err(format!("HTTP read failed: {}", e)),
        }
    }
    let text = String::from_utf8_lossy(&resp_buf).into_owned();
    let (hdr_part, body_part) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .ok_or_else(|| "Malformed HTTP response (missing header delimiter)".to_string())?;
    let status_line = hdr_part.lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| format!("Malformed HTTP status line: '{}'", status_line))?;
    Ok((status_code, body_part.to_string()))
}

pub fn exchange_token_live(
    endpoint: &str,
    subject_token: &str,
    subject_token_type: Option<&str>,
    requested_token_type: Option<&str>,
    audience: Option<&str>,
    grant_type: Option<&str>,
) -> LiveExchangeReport {
    let (scheme, host, port, path) = match parse_http_url(endpoint) {
        Ok(v) => v,
        Err(e) => {
            return LiveExchangeReport {
                status: "ERROR".to_string(),
                http_status: None,
                endpoint: endpoint.to_string(),
                access_token: None,
                issued_token_type: None,
                token_type: None,
                expires_in: None,
                error: Some("invalid_endpoint".to_string()),
                error_description: Some(e),
                raw_response_json: String::new(),
            };
        }
    };

    let grant = grant_type
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(RFC8693_TOKEN_EXCHANGE_GRANT);
    let stt = subject_token_type
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("urn:ietf:params:oauth:token-type:jwt");

    let mut form_pairs = vec![
        format!("grant_type={}", url_encode_component(grant.trim())),
        format!(
            "subject_token={}",
            url_encode_component(subject_token.trim())
        ),
        format!("subject_token_type={}", url_encode_component(stt.trim())),
    ];
    if let Some(rtt) = requested_token_type.filter(|s| !s.trim().is_empty()) {
        form_pairs.push(format!(
            "requested_token_type={}",
            url_encode_component(rtt.trim())
        ));
    }
    if let Some(aud) = audience.filter(|s| !s.trim().is_empty()) {
        form_pairs.push(format!("audience={}", url_encode_component(aud.trim())));
    }
    let encoded_body = form_pairs.join("&");

    let http_res = if scheme == "http" {
        raw_http_request(
            "POST",
            &host,
            port,
            &path,
            &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Accept", "application/json"),
                ("User-Agent", "Tanuki-Identity-Engine/2.0"),
            ],
            Some(encoded_body.as_bytes()),
            5000,
        )
    } else {
        let mut cmd = Command::new("curl");
        cmd.args([
            "-sS",
            "--proto",
            "=https",
            "--max-redirs",
            "0",
            "--max-time",
            "10",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/x-www-form-urlencoded",
            "-H",
            "Accept: application/json",
            "-H",
            "User-Agent: Tanuki-Identity-Engine/2.0",
            "--data-binary",
            "@-",
            "-w",
            "\n%{http_code}",
            endpoint,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

        match cmd.spawn() {
            Ok(mut child) => {
                if let Some(mut sin) = child.stdin.take() {
                    let _ = sin.write_all(encoded_body.as_bytes());
                }
                match child.wait_with_output() {
                    Ok(out) if out.status.success() => {
                        let stdout_str = String::from_utf8_lossy(&out.stdout);
                        if let Some((body_part, code_part)) =
                            stdout_str.trim_end().rsplit_once('\n')
                        {
                            if let Ok(code) = code_part.trim().parse::<u16>() {
                                Ok((code, body_part.to_string()))
                            } else {
                                Err("Failed to parse HTTP status code from curl transport"
                                    .to_string())
                            }
                        } else {
                            Err("Empty HTTP response from curl transport".to_string())
                        }
                    }
                    Ok(out) => Err(String::from_utf8_lossy(&out.stderr).trim().to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            Err(e) => Err(format!("HTTPS transport unavailable: {}", e)),
        }
    };

    match http_res {
        Ok((code, body_str)) => {
            let trimmed_body = body_str.trim();
            let parsed_json = parse_json(trimmed_body).ok();
            let raw_json_out = if parsed_json.is_some() {
                trimmed_body.to_string()
            } else {
                format!("{{\"raw_response\": \"{}\"}}", escape_json(trimmed_body))
            };

            if (200..300).contains(&code) {
                let access_token = parsed_json
                    .as_ref()
                    .and_then(|j| j.get("access_token"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let issued_token_type = parsed_json
                    .as_ref()
                    .and_then(|j| j.get("issued_token_type"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let token_type = parsed_json
                    .as_ref()
                    .and_then(|j| j.get("token_type"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let expires_in = parsed_json
                    .as_ref()
                    .and_then(|j| j.get("expires_in"))
                    .and_then(|v| v.as_i64());

                LiveExchangeReport {
                    status: "SUCCESS".to_string(),
                    http_status: Some(code),
                    endpoint: endpoint.to_string(),
                    access_token,
                    issued_token_type,
                    token_type,
                    expires_in,
                    error: None,
                    error_description: None,
                    raw_response_json: raw_json_out,
                }
            } else {
                let err_code = parsed_json
                    .as_ref()
                    .and_then(|j| j.get("error"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("http_error")
                    .to_string();
                let err_desc = parsed_json
                    .as_ref()
                    .and_then(|j| j.get("error_description"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("HTTP Error {}", code));

                LiveExchangeReport {
                    status: "ERROR".to_string(),
                    http_status: Some(code),
                    endpoint: endpoint.to_string(),
                    access_token: None,
                    issued_token_type: None,
                    token_type: None,
                    expires_in: None,
                    error: Some(err_code),
                    error_description: Some(err_desc),
                    raw_response_json: raw_json_out,
                }
            }
        }
        Err(err_msg) => LiveExchangeReport {
            status: "ERROR".to_string(),
            http_status: None,
            endpoint: endpoint.to_string(),
            access_token: None,
            issued_token_type: None,
            token_type: None,
            expires_in: None,
            error: Some("connection_failure".to_string()),
            error_description: Some(err_msg),
            raw_response_json: String::new(),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshIdentityItem {
    pub source: String,
    pub path: Option<String>,
    pub status: Option<String>,
    pub valid: Option<bool>,
    pub identity_type: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub token: Option<String>,
    pub details: Option<String>,
    pub error: Option<String>,
}

impl MeshIdentityItem {
    pub fn to_json(&self) -> String {
        let mut fields = Vec::new();
        fields.push(format!("    \"source\": \"{}\"", escape_json(&self.source)));
        if let Some(ref p) = self.path {
            fields.push(format!("    \"path\": \"{}\"", escape_json(p)));
        }
        if let Some(ref s) = self.status {
            fields.push(format!("    \"status\": \"{}\"", escape_json(s)));
        }
        if let Some(v) = self.valid {
            fields.push(format!("    \"valid\": {}", v));
        }
        if let Some(ref it) = self.identity_type {
            fields.push(format!("    \"identity_type\": \"{}\"", escape_json(it)));
        }
        if let Some(ref sub) = self.subject {
            fields.push(format!("    \"subject\": \"{}\"", escape_json(sub)));
        }
        if let Some(ref iss) = self.issuer {
            fields.push(format!("    \"issuer\": \"{}\"", escape_json(iss)));
        }
        if let Some(ref tok) = self.token {
            fields.push(format!("    \"token\": \"{}\"", escape_json(tok)));
        }
        if let Some(ref d) = self.details {
            fields.push(format!("    \"details\": \"{}\"", escape_json(d)));
        }
        if let Some(ref e) = self.error {
            fields.push(format!("    \"error\": \"{}\"", escape_json(e)));
        }
        format!("  {{\n{}\n  }}", fields.join(",\n"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshReport {
    pub status: String,
    pub discovered_identities: Vec<MeshIdentityItem>,
    pub count: usize,
}

impl MeshReport {
    pub fn to_json(&self) -> String {
        let items_str = if self.discovered_identities.is_empty() {
            "[]".to_string()
        } else {
            let body = self
                .discovered_identities
                .iter()
                .map(|i| i.to_json())
                .collect::<Vec<_>>()
                .join(",\n");
            format!("[\n{}\n  ]", body)
        };
        format!(
            "{{\n  \"status\": \"{}\",\n  \"discovered_identities\": {},\n  \"count\": {}\n}}",
            escape_json(&self.status),
            items_str,
            self.count
        )
    }

    pub fn format_terminal(&self) -> String {
        let mut out = String::new();
        out.push_str("[TANUKI CLOUD MESH IDENTITY INGESTION]\n");
        out.push_str(&format!(
            " SPIFFE / IMDS / Kubernetes Workload Ingestion · Found: {}\n",
            self.count
        ));
        if self.discovered_identities.is_empty() {
            out.push_str("[*] No active workload identity tokens found in local mesh.");
        } else {
            for (idx, item) in self.discovered_identities.iter().enumerate() {
                let branch = if idx + 1 == self.discovered_identities.len() {
                    "╰─"
                } else {
                    "├─"
                };
                let sub = item
                    .subject
                    .as_deref()
                    .or(item.details.as_deref())
                    .unwrap_or("");
                out.push_str(&format!("[+] Workload Identity [{}]\n", item.source));
                out.push_str(&format!("    {} {}\n", branch, sub));
            }
        }
        out.trim_end().to_string()
    }
}

pub fn discover_cloud_mesh(spiffe_socket: Option<&str>) -> MeshReport {
    let mut discovered = Vec::new();
    let k8s_paths = [
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/run/secrets/kubernetes.io/serviceaccount/token",
    ];
    for kp in &k8s_paths {
        let p = Path::new(kp);
        if p.is_file() {
            match crate::util::read_bytes_nofollow(p).and_then(|b| {
                String::from_utf8(b)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            }) {
                Ok(raw) => {
                    let tok = raw.trim().to_string();
                    match parse_and_validate_jwt(&tok, None, None) {
                        Ok(rep) => {
                            discovered.push(MeshIdentityItem {
                                source: "kubernetes_serviceaccount".to_string(),
                                path: Some(kp.to_string()),
                                status: None,
                                valid: Some(rep.valid),
                                identity_type: Some(rep.identity_type),
                                subject: rep.claims.sub,
                                issuer: rep.claims.iss,
                                token: Some(tok),
                                details: None,
                                error: None,
                            });
                        }
                        Err(e) => {
                            discovered.push(MeshIdentityItem {
                                source: "kubernetes_serviceaccount".to_string(),
                                path: Some(kp.to_string()),
                                status: None,
                                valid: None,
                                identity_type: None,
                                subject: None,
                                issuer: None,
                                token: None,
                                details: None,
                                error: Some(e),
                            });
                        }
                    }
                }
                Err(e) => {
                    discovered.push(MeshIdentityItem {
                        source: "kubernetes_serviceaccount".to_string(),
                        path: Some(kp.to_string()),
                        status: None,
                        valid: None,
                        identity_type: None,
                        subject: None,
                        issuer: None,
                        token: None,
                        details: None,
                        error: Some(e.to_string()),
                    });
                }
            }
        }
    }

    let spiffe_path = spiffe_socket.unwrap_or("/tmp/spire-agent/public/api.sock");
    if Path::new(spiffe_path).exists() {
        discovered.push(MeshIdentityItem {
            source: "spiffe_workload_api".to_string(),
            path: Some(spiffe_path.to_string()),
            status: Some("SOCKET_PRESENT".to_string()),
            valid: None,
            identity_type: None,
            subject: None,
            issuer: None,
            token: None,
            details: Some("Local SPIFFE agent socket available".to_string()),
            error: None,
        });
    }

    // Cloud IMDS fast non-blocking probe (AWS IMDSv2 -> Azure -> GCP)
    if let Ok((200, aws_tok)) = raw_http_request(
        "PUT",
        "169.254.169.254",
        80,
        "/latest/api/token",
        &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
        None,
        300,
    ) {
        let tok = aws_tok.trim().to_string();
        if !tok.is_empty() {
            discovered.push(MeshIdentityItem {
                source: "aws_imdsv2".to_string(),
                path: None,
                status: None,
                valid: None,
                identity_type: None,
                subject: None,
                issuer: None,
                token: Some(tok),
                details: Some("AWS IMDSv2 session token acquired".to_string()),
                error: None,
            });
        }
    } else if let Ok((200, az_body)) = raw_http_request(
        "GET",
        "169.254.169.254",
        80,
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F",
        &[("Metadata", "true")],
        None,
        300,
    ) {
        if let Ok(JsonValue::Object(entries)) = parse_json(az_body.trim()) {
            let tok = entries
                .into_iter()
                .find(|(k, _)| k == "access_token")
                .and_then(|(_, v)| v.as_str().map(|s| s.to_string()));
            discovered.push(MeshIdentityItem {
                source: "azure_imds".to_string(),
                path: None,
                status: None,
                valid: None,
                identity_type: None,
                subject: None,
                issuer: None,
                token: tok,
                details: Some("Azure Managed Identity token acquired".to_string()),
                error: None,
            });
        }
    } else if let Ok((200, gcp_tok)) = raw_http_request(
        "GET",
        "169.254.169.254",
        80,
        "/computeMetadata/v1/instance/service-accounts/default/identity?audience=https%3A%2F%2Fiam.googleapis.com%2F",
        &[("Metadata-Flavor", "Google")],
        None,
        300,
    ) {
        let tok = gcp_tok.trim().to_string();
        if !tok.is_empty() {
            discovered.push(MeshIdentityItem {
                source: "gcp_imds".to_string(),
                path: None,
                status: None,
                valid: None,
                identity_type: None,
                subject: None,
                issuer: None,
                token: Some(tok),
                details: Some("GCP Service Account OIDC token acquired".to_string()),
                error: None,
            });
        }
    }

    let count = discovered.len();
    let status = if count > 0 {
        "SUCCESS".to_string()
    } else {
        "NONE_DISCOVERED".to_string()
    };
    MeshReport {
        status,
        discovered_identities: discovered,
        count,
    }
}
