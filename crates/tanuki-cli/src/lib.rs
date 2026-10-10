#![forbid(unsafe_code)]

pub mod adcs;
pub mod config;
pub mod doctor;
pub mod fix;
pub mod kcm;
pub mod keytab;
pub mod ldap;
pub mod nhi;
pub mod pac;
pub mod protocol;
pub mod purge;
pub mod shadow;
pub mod util;

pub use adcs::{scan_adcs_source, AdcsFinding, AdcsReport};
pub use config::{discover_dc_via_srv, generate_krb5_conf};
pub use doctor::{run_doctor, CheckResult, DoctorOptions, DoctorReport};
pub use fix::{run_fix, FixAction, FixResult};
pub use kcm::{candidates_to_json, save_candidates, scan_for_ccache_blobs, CcacheCandidate};
pub use keytab::{entries_to_json, parse_keytab_bytes, KeytabEntry, KeytabError};
pub use ldap::{query_active_directory_ldap, LdapReport, LdapSearchEntry};
pub use nhi::{
    b64url_decode, parse_and_validate_jwt, validate_token_exchange, Finding, JwtClaims,
    JwtHeader, JwtValidationReport, SecurityEvaluation, TemporalStatus, TokenExchangeParams,
    TokenValidationReport,
};
pub use pac::{
    extract_pac_from_authorization_data, format_pac_report_terminal, pac_report_to_json,
    parse_nt_security_descriptor, parse_pac_bytes, parse_pac_source,
    parse_rbcd_security_descriptor, parse_windows_sid, AceDetail, PacReport,
    RbcdSecurityDescriptor,
};
pub use protocol::{
    calculate_clock_drift, calculate_remediated_clockskew, errors_to_json, find_error_resolution,
    ladder_to_json, parse_krb_error_stime, ErrorResolution, LadderRung, DECISION_LADDER,
    ERROR_DICTIONARY, FalcoRuleRef, SigmaRuleRef, TelemetryData,
};
pub use purge::{run_purge, shred_file, PurgeReport, ShredResult};
pub use shadow::{
    format_shadow_report_terminal, parse_cng_public_key, parse_key_credential_bytes,
    parse_key_credential_link, shadow_report_to_json, KeyMaterialInfo, ShadowCredentialReport,
};
pub use util::{escape_json, fill_dynamic_entropy, resolve_current_uid};
