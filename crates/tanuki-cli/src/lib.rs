#![forbid(unsafe_code)]

pub mod adcs;
pub mod blast;
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
pub use blast::{
    blast_report_to_json, classify_identity_tier, evaluate_blast_radius, extract_ad_account_name,
    format_blast_report_terminal, generate_ad_remediations, BlastReport, LateralPath,
    RemediationRecipe, TierInfo,
};
pub use config::{
    discover_dc_via_srv, generate_krb5_conf, parse_kdc_host_port, strip_kdc_transport_prefix,
};
pub use doctor::{
    enctype::audit_enctype_kvno, run_doctor, CheckResult, DoctorOptions, DoctorReport,
};
pub use fix::{run_fix, FixAction, FixResult};
pub use kcm::{candidates_to_json, save_candidates, scan_for_ccache_blobs, CcacheCandidate};
pub use keytab::{entries_to_json, parse_keytab_bytes, KeytabEntry, KeytabError};
pub use ldap::{
    build_ldap_bind_request, build_ldap_extensible_filter, build_ldap_search_filter,
    query_active_directory_ldap, LdapReport, LdapSearchEntry,
};
pub use nhi::{
    b64url_decode, discover_cloud_mesh, exchange_token_live, parse_and_validate_jwt,
    validate_token_exchange, Finding, JwtClaims, JwtHeader, JwtValidationReport,
    LiveExchangeReport, MeshIdentityItem, MeshReport, SecurityEvaluation, TemporalStatus,
    TokenExchangeParams, TokenValidationReport,
};
pub use pac::{
    extract_pac_from_authorization_data, format_pac_report_terminal, pac_report_to_json,
    parse_nt_security_descriptor, parse_pac_bytes, parse_pac_source,
    parse_rbcd_security_descriptor, parse_windows_sid, AceDetail, PacReport,
    RbcdSecurityDescriptor,
};
pub use protocol::{
    calculate_clock_drift, calculate_remediated_clockskew, errors_to_json, find_error_resolution,
    ladder_to_json, parse_krb_error_stime, ErrorResolution, FalcoRuleRef, LadderRung, SigmaRuleRef,
    TelemetryData, DECISION_LADDER, ERROR_DICTIONARY,
};
pub use purge::{run_purge, shred_file, PurgeReport, ShredResult};
pub use shadow::{
    format_shadow_report_terminal, parse_cng_public_key, parse_key_credential_bytes,
    parse_key_credential_link, shadow_report_to_json, KeyMaterialInfo, ShadowCredentialReport,
};
pub use util::{
    apply_nofollow, escape_json, fill_dynamic_entropy, open_regular_nofollow, read_bytes_nofollow,
    read_regular_nofollow_bounded, resolve_current_uid, sha256_digest, write_bytes_nofollow,
};
