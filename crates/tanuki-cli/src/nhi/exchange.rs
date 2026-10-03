use super::jwt::parse_and_validate_jwt;
use super::types::{TokenExchangeParams, TokenValidationReport};

pub const RFC8693_TOKEN_EXCHANGE_GRANT: &str =
    "urn:ietf:params:oauth:grant-type:token-exchange";

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
                    "INVALID_REQUEST: Missing required parameter 'grant_type'".to_string(),
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
            security_warnings.push(
                "WILDCARD_AUDIENCE: Dangerous wildcard audience detected: '*'".to_string(),
            );
        } else if aud.contains('*') {
            security_warnings.push(format!(
                "WILDCARD_AUDIENCE: Wildcard pattern in exchange audience: '{}'",
                aud
            ));
        }
    }

    let mut subject_report = None;
    if subject_token_type == "urn:ietf:params:oauth:token-type:jwt" {
        match parse_and_validate_jwt(subject_token, None) {
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
                        error_description: Some("The provided subject_token has expired".to_string()),
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
