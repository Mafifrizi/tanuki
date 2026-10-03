#![forbid(unsafe_code)]

pub mod config;
pub mod doctor;
pub mod kcm;
pub mod keytab;
pub mod nhi;
pub mod protocol;
pub mod util;

pub use config::generate_krb5_conf;
pub use doctor::{run_doctor, CheckResult, DoctorOptions, DoctorReport};
pub use kcm::{candidates_to_json, save_candidates, scan_for_ccache_blobs, CcacheCandidate};
pub use keytab::{entries_to_json, parse_keytab_bytes, KeytabEntry, KeytabError};
pub use nhi::{
    b64url_decode, parse_and_validate_jwt, validate_token_exchange, Finding, JwtClaims,
    JwtHeader, JwtValidationReport, SecurityEvaluation, TemporalStatus, TokenExchangeParams,
    TokenValidationReport,
};
pub use protocol::{
    errors_to_json, find_error_resolution, ladder_to_json, ErrorResolution, LadderRung,
    DECISION_LADDER, ERROR_DICTIONARY, FalcoRuleRef, SigmaRuleRef, TelemetryData,
};
pub use util::escape_json;
