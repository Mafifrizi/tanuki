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
pub mod util;

pub use adcs::{scan_adcs_source, AdcsFinding, AdcsReport};
pub use config::generate_krb5_conf;
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
    parse_pac_bytes, parse_pac_source, PacReport,
};
pub use protocol::{
    errors_to_json, find_error_resolution, ladder_to_json, ErrorResolution, LadderRung,
    DECISION_LADDER, ERROR_DICTIONARY, FalcoRuleRef, SigmaRuleRef, TelemetryData,
};
pub use purge::{run_purge, shred_file, PurgeReport, ShredResult};
pub use util::escape_json;
