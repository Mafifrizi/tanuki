#![forbid(unsafe_code)]

pub mod kcm;
pub mod keytab;
pub mod protocol;
pub mod util;

pub use kcm::{candidates_to_json, save_candidates, scan_for_ccache_blobs, CcacheCandidate};
pub use keytab::{entries_to_json, parse_keytab_bytes, KeytabEntry, KeytabError};
pub use protocol::{
    errors_to_json, find_error_resolution, ladder_to_json, ErrorResolution, LadderRung,
    DECISION_LADDER, ERROR_DICTIONARY,
};
pub use util::escape_json;
