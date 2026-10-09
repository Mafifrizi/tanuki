use crate::util::escape_json;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const CCACHE_MAGIC_V4: [u8; 2] = [0x05, 0x04];
const MAX_CANDIDATE_SIZE: usize = 65536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcacheCandidate {
    pub offset: usize,
    pub header_len: u16,
    pub payload_size: usize,
    pub default_principal: Option<String>,
    pub data: Vec<u8>,
}

impl CcacheCandidate {
    pub fn to_json(&self) -> String {
        let principal_str = match &self.default_principal {
            Some(p) => format!("\"{}\"", escape_json(p)),
            None => "null".to_string(),
        };

        format!(
            "  {{\n    \"offset\": {},\n    \"header_len\": {},\n    \"payload_size\": {},\n    \"default_principal\": {}\n  }}",
            self.offset, self.header_len, self.payload_size, principal_str
        )
    }
}

pub fn candidates_to_json(candidates: &[CcacheCandidate]) -> String {
    if candidates.is_empty() {
        return "[]".to_string();
    }
    let body = candidates
        .iter()
        .map(|c| c.to_json())
        .collect::<Vec<_>>()
        .join(",\n");
    format!("[\n{}\n]", body)
}

pub fn scan_for_ccache_blobs(data: &[u8]) -> Vec<CcacheCandidate> {
    let mut results = Vec::new();
    let mut offset = 0;

    while offset + 4 <= data.len() {
        if let Some(pos) = find_magic(&data[offset..]) {
            let abs_pos = offset + pos;
            if abs_pos + 4 <= data.len() {
                let header_len =
                    u16::from_be_bytes([data[abs_pos + 2], data[abs_pos + 3]]) as usize;
                if abs_pos + 4 + header_len <= data.len() {
                    let end = (abs_pos + MAX_CANDIDATE_SIZE).min(data.len());
                    let blob = data[abs_pos..end].to_vec();
                    let principal =
                        try_parse_default_principal(&data[abs_pos + 4 + header_len..end]);

                    results.push(CcacheCandidate {
                        offset: abs_pos,
                        header_len: header_len as u16,
                        payload_size: blob.len(),
                        default_principal: principal,
                        data: blob,
                    });
                }
            }
            offset = abs_pos + 2;
        } else {
            break;
        }
    }

    results
}

fn find_magic(slice: &[u8]) -> Option<usize> {
    slice
        .windows(2)
        .position(|w| w == CCACHE_MAGIC_V4)
}

fn try_parse_default_principal(slice: &[u8]) -> Option<String> {
    if slice.len() < 12 {
        return None;
    }

    let _name_type = u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]);
    let num_components = u32::from_be_bytes([slice[4], slice[5], slice[6], slice[7]]) as usize;
    let realm_len = u32::from_be_bytes([slice[8], slice[9], slice[10], slice[11]]) as usize;

    if num_components == 0 || num_components > 16 || realm_len == 0 || realm_len > 256 {
        return None;
    }

    let mut cursor = 12;
    if cursor + realm_len > slice.len() {
        return None;
    }

    let realm = std::str::from_utf8(&slice[cursor..cursor + realm_len]).ok()?;
    cursor += realm_len;

    let mut components = Vec::with_capacity(num_components);
    for _ in 0..num_components {
        if cursor + 4 > slice.len() {
            return None;
        }
        let comp_len = u32::from_be_bytes([
            slice[cursor],
            slice[cursor + 1],
            slice[cursor + 2],
            slice[cursor + 3],
        ]) as usize;
        cursor += 4;

        if comp_len == 0 || comp_len > 256 || cursor + comp_len > slice.len() {
            return None;
        }
        let comp = std::str::from_utf8(&slice[cursor..cursor + comp_len]).ok()?;
        components.push(comp);
        cursor += comp_len;
    }

    Some(format!("{}@{}", components.join("/"), realm))
}

pub fn save_candidates(
    candidates: &[CcacheCandidate],
    out_dir: &Path,
    prefix: &str,
) -> std::io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(out_dir)?;
    let mut written = Vec::new();

    for (idx, candidate) in candidates.iter().enumerate() {
        let file_name = if prefix == "ticket" {
            format!("ticket_{}.ccache", idx + 1)
        } else {
            format!("{}_recovered_{}.ccache", prefix, idx + 1)
        };
        let path = out_dir.join(file_name);
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&path)?;
        file.write_all(&candidate.data)?;
        written.push(path);
    }

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_for_ccache_blobs_basic() {
        let mut fake_db = b"RANDOM_LDB_RECORDS_DATA_PADDING".to_vec();

        let mut valid_ccache = vec![0x05, 0x04];
        valid_ccache.extend_from_slice(&12u16.to_be_bytes());
        valid_ccache.extend_from_slice(&[0x41; 50]);

        fake_db.extend_from_slice(&valid_ccache);
        fake_db.extend_from_slice(b"MORE_PADDING_DATA");

        let candidates = scan_for_ccache_blobs(&fake_db);
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].header_len, 12);
        assert!(candidates[0].data.starts_with(&[0x05, 0x04]));
    }

    #[test]
    fn test_scan_with_principal_extraction() {
        let mut blob = vec![0x05, 0x04];
        blob.extend_from_slice(&0u16.to_be_bytes());
        blob.extend_from_slice(&1u32.to_be_bytes());
        blob.extend_from_slice(&1u32.to_be_bytes());
        let realm = b"CORP.LOCAL";
        blob.extend_from_slice(&(realm.len() as u32).to_be_bytes());
        blob.extend_from_slice(realm);
        let comp = b"admin";
        blob.extend_from_slice(&(comp.len() as u32).to_be_bytes());
        blob.extend_from_slice(comp);

        let candidates = scan_for_ccache_blobs(&blob);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].default_principal,
            Some("admin@CORP.LOCAL".to_string())
        );
    }

    #[test]
    fn test_rejects_empty_realm_principal() {
        let mut blob = vec![0x05, 0x04];
        blob.extend_from_slice(&0u16.to_be_bytes());
        blob.extend_from_slice(&1u32.to_be_bytes());
        blob.extend_from_slice(&1u32.to_be_bytes());
        blob.extend_from_slice(&0u32.to_be_bytes()); // realm_len = 0
        let candidates = scan_for_ccache_blobs(&blob);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].default_principal, None);
    }
}
