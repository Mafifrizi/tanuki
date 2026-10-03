use crate::util::escape_json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
    pub kid: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct JwtClaims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Vec<String>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporalStatus {
    pub is_expired: Option<bool>,
    pub remaining_seconds: Option<i64>,
    pub remaining_human: String,
    pub lifetime_seconds: Option<i64>,
    pub is_ephemeral: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvaluation {
    pub has_wildcard_audience: bool,
    pub has_broad_subject_scope: bool,
    pub insecure_algorithm: bool,
    pub risk_level: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct JwtValidationReport {
    pub valid: bool,
    pub identity_type: String,
    pub header: JwtHeader,
    pub claims: JwtClaims,
    pub temporal: TemporalStatus,
    pub security_evaluation: SecurityEvaluation,
    pub security_warnings: Vec<String>,
}

impl JwtValidationReport {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"valid\": {},\n", self.valid));
        out.push_str(&format!(
            "  \"identity_type\": \"{}\",\n",
            escape_json(&self.identity_type)
        ));
        out.push_str("  \"header\": {\n");
        out.push_str(&format!("    \"alg\": \"{}\"", escape_json(&self.header.alg)));
        if let Some(typ) = &self.header.typ {
            out.push_str(&format!(",\n    \"typ\": \"{}\"", escape_json(typ)));
        }
        if let Some(kid) = &self.header.kid {
            out.push_str(&format!(",\n    \"kid\": \"{}\"", escape_json(kid)));
        }
        out.push_str("\n  },\n");

        out.push_str("  \"claims\": {\n");
        let mut claims_parts = Vec::new();
        if let Some(iss) = &self.claims.iss {
            claims_parts.push(format!("    \"iss\": \"{}\"", escape_json(iss)));
        }
        if let Some(sub) = &self.claims.sub {
            claims_parts.push(format!("    \"sub\": \"{}\"", escape_json(sub)));
        }
        if !self.claims.aud.is_empty() {
            if self.claims.aud.len() == 1 {
                claims_parts.push(format!(
                    "    \"aud\": \"{}\"",
                    escape_json(&self.claims.aud[0])
                ));
            } else {
                let aud_items = self
                    .claims
                    .aud
                    .iter()
                    .map(|a| format!("\"{}\"", escape_json(a)))
                    .collect::<Vec<_>>()
                    .join(", ");
                claims_parts.push(format!("    \"aud\": [{}]", aud_items));
            }
        }
        if let Some(exp) = self.claims.exp {
            claims_parts.push(format!("    \"exp\": {}", exp));
        }
        if let Some(nbf) = self.claims.nbf {
            claims_parts.push(format!("    \"nbf\": {}", nbf));
        }
        if let Some(iat) = self.claims.iat {
            claims_parts.push(format!("    \"iat\": {}", iat));
        }
        out.push_str(&claims_parts.join(",\n"));
        out.push_str("\n  },\n");

        out.push_str("  \"temporal\": {\n");
        match self.temporal.is_expired {
            Some(exp) => out.push_str(&format!("    \"is_expired\": {},\n", exp)),
            None => out.push_str("    \"is_expired\": null,\n"),
        }
        match self.temporal.remaining_seconds {
            Some(rem) => out.push_str(&format!("    \"remaining_seconds\": {},\n", rem)),
            None => out.push_str("    \"remaining_seconds\": null,\n"),
        }
        out.push_str(&format!(
            "    \"remaining_human\": \"{}\",\n",
            escape_json(&self.temporal.remaining_human)
        ));
        match self.temporal.lifetime_seconds {
            Some(lt) => out.push_str(&format!("    \"lifetime_seconds\": {},\n", lt)),
            None => out.push_str("    \"lifetime_seconds\": null,\n"),
        }
        out.push_str(&format!(
            "    \"is_ephemeral\": {}\n",
            self.temporal.is_ephemeral
        ));
        out.push_str("  },\n");

        out.push_str("  \"security_evaluation\": {\n");
        out.push_str(&format!(
            "    \"has_wildcard_audience\": {},\n",
            self.security_evaluation.has_wildcard_audience
        ));
        out.push_str(&format!(
            "    \"has_broad_subject_scope\": {},\n",
            self.security_evaluation.has_broad_subject_scope
        ));
        out.push_str(&format!(
            "    \"insecure_algorithm\": {},\n",
            self.security_evaluation.insecure_algorithm
        ));
        out.push_str(&format!(
            "    \"risk_level\": \"{}\",\n",
            escape_json(&self.security_evaluation.risk_level)
        ));
        out.push_str("    \"findings\": [\n");
        let findings_json = self
            .security_evaluation
            .findings
            .iter()
            .map(|f| {
                format!(
                    "      {{\n        \"severity\": \"{}\",\n        \"code\": \"{}\",\n        \"message\": \"{}\"\n      }}",
                    escape_json(&f.severity),
                    escape_json(&f.code),
                    escape_json(&f.message)
                )
            })
            .collect::<Vec<_>>()
            .join(",\n");
        out.push_str(&findings_json);
        out.push_str("\n    ]\n");
        out.push_str("  },\n");

        out.push_str("  \"security_warnings\": [\n");
        let warnings_json = self
            .security_warnings
            .iter()
            .map(|w| format!("    \"{}\"", escape_json(w)))
            .collect::<Vec<_>>()
            .join(",\n");
        out.push_str(&warnings_json);
        out.push_str("\n  ]\n");
        out.push_str("}");
        out
    }

    pub fn format_terminal(&self) -> String {
        let mut out = String::new();
        out.push_str(&"=".repeat(72));
        out.push('\n');
        out.push_str(" TANUKI WORKLOAD IDENTITY VALIDATOR (RFC 8693 / NHI)\n");
        out.push_str(&"=".repeat(72));
        out.push('\n');

        out.push_str(&format!("Identity Type    : {}\n", self.identity_type));
        if let Some(iss) = &self.claims.iss {
            out.push_str(&format!("Issuer (iss)     : {}\n", iss));
        }
        if let Some(sub) = &self.claims.sub {
            out.push_str(&format!("Subject (sub)    : {}\n", sub));
        }
        if !self.claims.aud.is_empty() {
            out.push_str(&format!("Audience (aud)   : {}\n", self.claims.aud.join(", ")));
        }

        let kid_info = match &self.header.kid {
            Some(k) => format!(" | Key ID: {}", k),
            None => String::new(),
        };
        out.push_str(&format!("Algorithm (alg)  : {}{}\n\n", self.header.alg, kid_info));

        out.push_str("TEMPORAL STATUS:\n");
        if let Some(iat) = self.claims.iat {
            out.push_str(&format!("Issued At (iat)  : {}\n", iat));
        }
        if let Some(exp) = self.claims.exp {
            out.push_str(&format!("Expires At (exp) : {}\n", exp));
        }
        let status_str = if self.temporal.is_expired.unwrap_or(false) {
            "EXPIRED"
        } else {
            "ACTIVE"
        };
        out.push_str(&format!(
            "Remaining Time   : {} ({})\n",
            self.temporal.remaining_human, status_str
        ));
        if let Some(lt) = self.temporal.lifetime_seconds {
            out.push_str(&format!("Lifetime Span    : {}s\n", lt));
        }
        out.push('\n');

        out.push_str("SECURITY POLICY EVALUATION:\n");
        if self.security_evaluation.findings.is_empty() {
            out.push_str("[SAFE] All security policies satisfied\n");
        } else {
            for f in &self.security_evaluation.findings {
                let tag = match f.severity.as_str() {
                    "LOW" => "SAFE",
                    "MEDIUM" => "WARN",
                    _ => "CRITICAL",
                };
                out.push_str(&format!("[{}] {} : {}\n", tag, f.code, f.message));
            }
        }
        out.push('\n');

        let assessment = if self.valid {
            "VALID & SECURE"
        } else {
            "INVALID OR HIGH RISK"
        };
        out.push_str(&format!("OVERALL ASSESSMENT: {}\n", assessment));
        out.push_str(&"=".repeat(72));
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TokenExchangeParams {
    pub grant_type: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub requested_token_type: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenValidationReport {
    pub valid: bool,
    pub exchange_valid: bool,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub parameters: TokenExchangeParams,
    pub security_warnings: Vec<String>,
    pub subject_token_report: Option<JwtValidationReport>,
}

impl TokenValidationReport {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"valid\": {},\n", self.valid));
        out.push_str(&format!("  \"exchange_valid\": {},\n", self.exchange_valid));
        match &self.error {
            Some(err) => out.push_str(&format!("  \"error\": \"{}\",\n", escape_json(err))),
            None => out.push_str("  \"error\": null,\n"),
        }
        match &self.error_description {
            Some(desc) => {
                out.push_str(&format!("  \"error_description\": \"{}\",\n", escape_json(desc)))
            }
            None => out.push_str("  \"error_description\": null,\n"),
        }

        out.push_str("  \"parameters\": {\n");
        let mut param_entries = Vec::new();
        if let Some(gt) = &self.parameters.grant_type {
            param_entries.push(format!("    \"grant_type\": \"{}\"", escape_json(gt)));
        }
        if let Some(st) = &self.parameters.subject_token {
            param_entries.push(format!("    \"subject_token\": \"{}\"", escape_json(st)));
        }
        if let Some(stt) = &self.parameters.subject_token_type {
            param_entries.push(format!("    \"subject_token_type\": \"{}\"", escape_json(stt)));
        }
        if let Some(rtt) = &self.parameters.requested_token_type {
            param_entries.push(format!("    \"requested_token_type\": \"{}\"", escape_json(rtt)));
        }
        if let Some(aud) = &self.parameters.audience {
            param_entries.push(format!("    \"audience\": \"{}\"", escape_json(aud)));
        }
        out.push_str(&param_entries.join(",\n"));
        out.push_str("\n  },\n");

        out.push_str("  \"security_warnings\": [\n");
        let warnings_json = self
            .security_warnings
            .iter()
            .map(|w| format!("    \"{}\"", escape_json(w)))
            .collect::<Vec<_>>()
            .join(",\n");
        out.push_str(&warnings_json);
        out.push_str("\n  ]");

        if let Some(sub_rep) = &self.subject_token_report {
            out.push_str(",\n  \"subject_token_report\": ");
            out.push_str(&sub_rep.to_json());
        } else {
            out.push_str(",\n  \"subject_token_report\": null");
        }

        out.push_str("\n}");
        out
    }

    pub fn format_terminal(&self) -> String {
        let mut out = String::new();
        out.push_str(&"=".repeat(72));
        out.push('\n');
        out.push_str(" TANUKI RFC 8693 TOKEN EXCHANGE VALIDATION REPORT\n");
        out.push_str(&"=".repeat(72));
        out.push('\n');

        let status = if self.valid { "VALID" } else { "FAILED" };
        out.push_str(&format!("Exchange Status   : {}\n", status));
        if let Some(err) = &self.error {
            out.push_str(&format!("Error Code        : {}\n", err));
        }
        if let Some(desc) = &self.error_description {
            out.push_str(&format!("Description       : {}\n", desc));
        }

        if !self.security_warnings.is_empty() {
            out.push_str("\nSecurity Warnings:\n");
            for w in &self.security_warnings {
                out.push_str(&format!("  [!] {}\n", w));
            }
        }

        out.push_str(&"=".repeat(72));
        out
    }
}
