use std::time::{SystemTime, UNIX_EPOCH};

use super::types::{
    Finding, JwtClaims, JwtHeader, JwtValidationReport, SecurityEvaluation, TemporalStatus,
};

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(entries) => {
                for (k, v) in entries {
                    if k == key {
                        return Some(v);
                    }
                }
                None
            }
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Number(n) => Some(*n as i64),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            JsonValue::Array(a) => Some(a),
            _ => None,
        }
    }
}

pub struct JsonParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> JsonParser<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        if let Some(c) = self.peek() {
            self.pos += c.len_utf8();
            Some(c)
        } else {
            None
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    pub fn parse(&mut self) -> Result<JsonValue, String> {
        self.skip_whitespace();
        let val = self.parse_value()?;
        self.skip_whitespace();
        Ok(val)
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        self.skip_whitespace();
        match self.peek() {
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('{') => self.parse_object().map(JsonValue::Object),
            Some('[') => self.parse_array().map(JsonValue::Array),
            Some('t') | Some('f') => self.parse_bool().map(JsonValue::Bool),
            Some('n') => self.parse_null().map(|_| JsonValue::Null),
            Some(c) if c.is_ascii_digit() || c == '-' => self.parse_number().map(JsonValue::Number),
            Some(other) => Err(format!("Unexpected character in JSON: '{}'", other)),
            None => Err("Unexpected end of JSON input".to_string()),
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.advance() != Some('"') {
            return Err("Expected '\"' at start of string".to_string());
        }
        let mut result = String::new();
        while let Some(c) = self.advance() {
            match c {
                '"' => return Ok(result),
                '\\' => {
                    let esc = match self.advance() {
                        Some('"') => '"',
                        Some('\\') => '\\',
                        Some('/') => '/',
                        Some('b') => '\x08',
                        Some('f') => '\x0c',
                        Some('n') => '\n',
                        Some('r') => '\r',
                        Some('t') => '\t',
                        Some('u') => {
                            let mut hex = String::new();
                            for _ in 0..4 {
                                if let Some(h) = self.advance() {
                                    hex.push(h);
                                } else {
                                    return Err("Truncated unicode escape in string".to_string());
                                }
                            }
                            let code = u32::from_str_radix(&hex, 16)
                                .map_err(|e| format!("Invalid unicode escape: {}", e))?;
                            char::from_u32(code).unwrap_or('\u{FFFD}')
                        }
                        Some(other) => return Err(format!("Invalid escape sequence: \\{}", other)),
                        None => return Err("Unterminated escape sequence".to_string()),
                    };
                    result.push(esc);
                }
                normal => result.push(normal),
            }
        }
        Err("Unterminated JSON string".to_string())
    }

    fn parse_object(&mut self) -> Result<Vec<(String, JsonValue)>, String> {
        if self.advance() != Some('{') {
            return Err("Expected '{' at start of object".to_string());
        }
        let mut entries = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some('}') {
            self.advance();
            return Ok(entries);
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            if self.advance() != Some(':') {
                return Err("Expected ':' after key in object".to_string());
            }
            let val = self.parse_value()?;
            entries.push((key, val));
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.advance();
                }
                Some('}') => {
                    self.advance();
                    break;
                }
                Some(other) => return Err(format!("Expected ',' or '}}' in object, got '{}'", other)),
                None => return Err("Unterminated object".to_string()),
            }
        }
        Ok(entries)
    }

    fn parse_array(&mut self) -> Result<Vec<JsonValue>, String> {
        if self.advance() != Some('[') {
            return Err("Expected '[' at start of array".to_string());
        }
        let mut list = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(']') {
            self.advance();
            return Ok(list);
        }

        loop {
            let val = self.parse_value()?;
            list.push(val);
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.advance();
                }
                Some(']') => {
                    self.advance();
                    break;
                }
                Some(other) => return Err(format!("Expected ',' or ']' in array, got '{}'", other)),
                None => return Err("Unterminated array".to_string()),
            }
        }
        Ok(list)
    }

    fn parse_bool(&mut self) -> Result<bool, String> {
        if self.input[self.pos..].starts_with("true") {
            self.pos += 4;
            Ok(true)
        } else if self.input[self.pos..].starts_with("false") {
            self.pos += 5;
            Ok(false)
        } else {
            Err("Expected boolean literal".to_string())
        }
    }

    fn parse_null(&mut self) -> Result<(), String> {
        if self.input[self.pos..].starts_with("null") {
            self.pos += 4;
            Ok(())
        } else {
            Err("Expected null literal".to_string())
        }
    }

    fn parse_number(&mut self) -> Result<f64, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.advance();
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-' {
                self.advance();
            } else {
                break;
            }
        }
        let num_str = &self.input[start..self.pos];
        num_str
            .parse::<f64>()
            .map_err(|e| format!("Invalid number '{}': {}", num_str, e))
    }
}

pub fn parse_json(input: &str) -> Result<JsonValue, String> {
    let mut parser = JsonParser::new(input);
    parser.parse()
}

pub fn b64url_decode(input: &str) -> Result<Vec<u8>, String> {
    let clean_str = input.trim().trim_end_matches('=');
    let mut clean = Vec::with_capacity(clean_str.len());
    for b in clean_str.bytes() {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'\r' | b'\n' | b' ' => continue,
            _ => return Err(format!("Invalid character in base64url stream: {}", b as char)),
        };
        clean.push(val);
    }
    if clean.len() % 4 == 1 {
        return Err("Invalid Base64URL encoding (data character length cannot be 1 mod 4)".to_string());
    }
    let mut out = Vec::new();
    let mut chunks = clean.chunks_exact(4);
    for chunk in chunks.by_ref() {
        out.push((chunk[0] << 2) | (chunk[1] >> 4));
        out.push((chunk[1] << 4) | (chunk[2] >> 2));
        out.push((chunk[2] << 6) | chunk[3]);
    }
    let rem = chunks.remainder();
    if rem.len() == 2 {
        out.push((rem[0] << 2) | (rem[1] >> 4));
    } else if rem.len() == 3 {
        out.push((rem[0] << 2) | (rem[1] >> 4));
        out.push((rem[1] << 4) | (rem[2] >> 2));
    }
    Ok(out)
}

fn detect_identity_type(claims: &JsonValue) -> String {
    let iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");

    if iss.contains("kubernetes") || sub.starts_with("system:serviceaccount:") {
        "Kubernetes ServiceAccount Token".to_string()
    } else if iss.contains("actions.githubusercontent.com") || sub.starts_with("repo:") {
        "GitHub Actions OIDC Token".to_string()
    } else if sub.starts_with("spiffe://") || iss.starts_with("spiffe://") {
        "SPIFFE SVID".to_string()
    } else if iss.contains("amazonaws.com") || iss.contains("aws") {
        "AWS IAM Workload Identity".to_string()
    } else {
        "Workload Identity Token".to_string()
    }
}

pub fn parse_and_validate_jwt(
    token: &str,
    expected_aud: Option<&str>,
) -> Result<JwtValidationReport, String> {
    let clean = token.trim();
    if clean.is_empty() {
        return Err("Token string is empty".to_string());
    }

    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() != 3 {
        return Err(format!(
            "Invalid JWT format: expected 3 period-delimited segments, got {}",
            parts.len()
        ));
    }

    let header_bytes = b64url_decode(parts[0])?;
    let header_str = String::from_utf8(header_bytes)
        .map_err(|e| format!("Header is not valid UTF-8: {}", e))?;
    let header_json = parse_json(&header_str)?;

    let payload_bytes = b64url_decode(parts[1])?;
    let payload_str = String::from_utf8(payload_bytes)
        .map_err(|e| format!("Payload is not valid UTF-8: {}", e))?;
    let payload_json = parse_json(&payload_str)?;

    let alg = header_json
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("none")
        .to_string();
    let typ = header_json
        .get("typ")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let kid = header_json
        .get("kid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let iss = payload_json
        .get("iss")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let sub = payload_json
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut aud = Vec::new();
    if let Some(aud_val) = payload_json.get("aud") {
        if let Some(s) = aud_val.as_str() {
            aud.push(s.to_string());
        } else if let Some(arr) = aud_val.as_array() {
            for item in arr {
                if let Some(s) = item.as_str() {
                    aud.push(s.to_string());
                }
            }
        }
    }

    let exp = payload_json.get("exp").and_then(|v| v.as_i64());
    let nbf = payload_json.get("nbf").and_then(|v| v.as_i64());
    let iat = payload_json.get("iat").and_then(|v| v.as_i64());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let is_expired = exp.map(|e| e <= now);
    let remaining_seconds = exp.map(|e| e - now);
    let remaining_human = match remaining_seconds {
        Some(rem) if rem <= 0 => "Expired".to_string(),
        Some(rem) => {
            let hrs = rem / 3600;
            let mins = (rem % 3600) / 60;
            let secs = rem % 60;
            if hrs > 0 {
                format!("{}h {}m {}s", hrs, mins, secs)
            } else if mins > 0 {
                format!("{}m {}s", mins, secs)
            } else {
                format!("{}s", secs)
            }
        }
        None => "No Expiration".to_string(),
    };

    let lifetime_seconds = match (exp, iat) {
        (Some(e), Some(i)) => Some(e - i),
        _ => None,
    };
    let is_ephemeral = lifetime_seconds.map(|lt| lt <= 86400).unwrap_or(true);

    let identity_type = detect_identity_type(&payload_json);

    let mut findings = Vec::new();
    let mut security_warnings = Vec::new();

    let mut has_wildcard_audience = false;
    if aud.is_empty() {
        has_wildcard_audience = true;
        let msg = "Audience claim is missing or empty".to_string();
        findings.push(Finding {
            severity: "HIGH".to_string(),
            code: "MISSING_AUDIENCE".to_string(),
            message: msg.clone(),
        });
        security_warnings.push(format!("MISSING_AUDIENCE: {}", msg));
    } else if aud.iter().any(|a| a == "*") {
        has_wildcard_audience = true;
        let msg = "Dangerous wildcard audience detected: '*'".to_string();
        findings.push(Finding {
            severity: "CRITICAL".to_string(),
            code: "WILDCARD_AUDIENCE".to_string(),
            message: msg.clone(),
        });
        security_warnings.push(format!("WILDCARD_AUDIENCE: {}", msg));
    } else if aud.iter().any(|a| a.contains('*')) {
        has_wildcard_audience = true;
        let msg = format!("Wildcard pattern in audience: {}", aud.join(", "));
        findings.push(Finding {
            severity: "HIGH".to_string(),
            code: "WILDCARD_AUDIENCE".to_string(),
            message: msg.clone(),
        });
        security_warnings.push(format!("WILDCARD_AUDIENCE: {}", msg));
    } else if let Some(expected) = expected_aud {
        if !aud.iter().any(|a| a == expected) {
            let msg = format!("Token audience does not match expected audience '{}'", expected);
            findings.push(Finding {
                severity: "HIGH".to_string(),
                code: "AUDIENCE_MISMATCH".to_string(),
                message: msg.clone(),
            });
            security_warnings.push(format!("AUDIENCE_MISMATCH: {}", msg));
        }
    }

    let mut has_broad_subject_scope = false;
    if let Some(sub_str) = &sub {
        if sub_str.starts_with("system:serviceaccount:") {
            let parts: Vec<&str> = sub_str.split(':').collect();
            if parts.len() >= 4 && parts[2] == "*" {
                has_broad_subject_scope = true;
                let msg = format!("Wildcard namespace in Kubernetes ServiceAccount: {}", sub_str);
                findings.push(Finding {
                    severity: "CRITICAL".to_string(),
                    code: "OVERLY_BROAD_SUBJECT".to_string(),
                    message: msg.clone(),
                });
                security_warnings.push(format!("OVERLY_BROAD_SUBJECT: {}", msg));
            } else if parts.len() >= 4 && parts[3] == "*" {
                has_broad_subject_scope = true;
                let msg = format!("Wildcard service account name: {}", sub_str);
                findings.push(Finding {
                    severity: "HIGH".to_string(),
                    code: "OVERLY_BROAD_SUBJECT".to_string(),
                    message: msg.clone(),
                });
                security_warnings.push(format!("OVERLY_BROAD_SUBJECT: {}", msg));
            } else if sub_str.contains('*') {
                has_broad_subject_scope = true;
                let msg = format!("Wildcard pattern in Kubernetes ServiceAccount: {}", sub_str);
                findings.push(Finding {
                    severity: "HIGH".to_string(),
                    code: "OVERLY_BROAD_SUBJECT".to_string(),
                    message: msg.clone(),
                });
                security_warnings.push(format!("OVERLY_BROAD_SUBJECT: {}", msg));
            }
        } else if sub_str.starts_with("repo:") {
            if sub_str.contains('*') {
                has_broad_subject_scope = true;
                let msg = format!("Wildcard repository pattern in GitHub OIDC subject: {}", sub_str);
                findings.push(Finding {
                    severity: "HIGH".to_string(),
                    code: "OVERLY_BROAD_SUBJECT".to_string(),
                    message: msg.clone(),
                });
                security_warnings.push(format!("OVERLY_BROAD_SUBJECT: {}", msg));
            }
        } else if sub_str.starts_with("spiffe://") {
            if sub_str.contains('*') {
                has_broad_subject_scope = true;
                let msg = format!("Wildcard pattern in SPIFFE ID: {}", sub_str);
                findings.push(Finding {
                    severity: "CRITICAL".to_string(),
                    code: "OVERLY_BROAD_SUBJECT".to_string(),
                    message: msg.clone(),
                });
                security_warnings.push(format!("OVERLY_BROAD_SUBJECT: {}", msg));
            }
        } else if sub_str.contains('*') {
            has_broad_subject_scope = true;
            let msg = format!("Wildcard pattern in subject scope: {}", sub_str);
            findings.push(Finding {
                severity: "HIGH".to_string(),
                code: "OVERLY_BROAD_SUBJECT".to_string(),
                message: msg.clone(),
            });
            security_warnings.push(format!("OVERLY_BROAD_SUBJECT: {}", msg));
        }
    }

    let mut insecure_algorithm = false;
    if alg.eq_ignore_ascii_case("none") {
        insecure_algorithm = true;
        let msg = "Unsecured JWT (alg=none) detected".to_string();
        findings.push(Finding {
            severity: "CRITICAL".to_string(),
            code: "INSECURE_ALGORITHM".to_string(),
            message: msg.clone(),
        });
        security_warnings.push(format!("INSECURE_ALGORITHM: {}", msg));
    } else if alg.to_uppercase().starts_with("HS") {
        let msg = format!("Symmetric algorithm {} used instead of asymmetric for workload identity", alg);
        findings.push(Finding {
            severity: "MEDIUM".to_string(),
            code: "SYMMETRIC_ALGORITHM".to_string(),
            message: msg.clone(),
        });
        security_warnings.push(format!("SYMMETRIC_ALGORITHM: {}", msg));
    }

    if exp.is_none() {
        let msg = "Token has no expiration (exp) claim".to_string();
        findings.push(Finding {
            severity: "HIGH".to_string(),
            code: "MISSING_EXPIRATION".to_string(),
            message: msg.clone(),
        });
        security_warnings.push(format!("MISSING_EXPIRATION: {}", msg));
    } else if is_expired == Some(true) {
        let msg = "Token has expired".to_string();
        findings.push(Finding {
            severity: "CRITICAL".to_string(),
            code: "TOKEN_EXPIRED".to_string(),
            message: msg.clone(),
        });
        security_warnings.push(format!("TOKEN_EXPIRED: {}", msg));
    }

    if let Some(nbf_val) = nbf {
        if now < nbf_val {
            let msg = format!("Token is not yet valid (nbf={} in future)", nbf_val);
            findings.push(Finding {
                severity: "HIGH".to_string(),
                code: "TOKEN_NOT_YET_VALID".to_string(),
                message: msg.clone(),
            });
            security_warnings.push(format!("TOKEN_NOT_YET_VALID: {}", msg));
        }
    }

    if let Some(lt) = lifetime_seconds {
        if lt > 86400 {
            let msg = format!("Token lifetime ({}s) exceeds 24h threshold for ephemeral workloads", lt);
            findings.push(Finding {
                severity: "MEDIUM".to_string(),
                code: "EXCESSIVE_LIFETIME".to_string(),
                message: msg.clone(),
            });
            security_warnings.push(format!("EXCESSIVE_LIFETIME: {}", msg));
        }
    }

    let risk_level = if findings.iter().any(|f| f.severity == "CRITICAL") {
        "CRITICAL".to_string()
    } else if findings.iter().any(|f| f.severity == "HIGH") {
        "HIGH".to_string()
    } else if findings.iter().any(|f| f.severity == "MEDIUM") {
        "MEDIUM".to_string()
    } else {
        findings.push(Finding {
            severity: "LOW".to_string(),
            code: "SAFE_TOKEN".to_string(),
            message: "Token claims and security boundaries are valid".to_string(),
        });
        "LOW".to_string()
    };

    let mut valid = true;
    if is_expired == Some(true) || is_expired.is_none() {
        valid = false;
    }
    if insecure_algorithm {
        valid = false;
    }
    if has_wildcard_audience {
        valid = false;
    }
    if has_broad_subject_scope {
        valid = false;
    }
    if expected_aud.is_some() && findings.iter().any(|f| f.code == "AUDIENCE_MISMATCH") {
        valid = false;
    }
    if let Some(nbf_val) = nbf {
        if now < nbf_val {
            valid = false;
        }
    }

    Ok(JwtValidationReport {
        valid,
        identity_type,
        header: JwtHeader { alg, typ, kid },
        claims: JwtClaims {
            iss,
            sub,
            aud,
            exp,
            nbf,
            iat,
        },
        temporal: TemporalStatus {
            is_expired,
            remaining_seconds,
            remaining_human,
            lifetime_seconds,
            is_ephemeral,
        },
        security_evaluation: SecurityEvaluation {
            has_wildcard_audience,
            has_broad_subject_scope,
            insecure_algorithm,
            risk_level,
            findings,
        },
        security_warnings,
    })
}
