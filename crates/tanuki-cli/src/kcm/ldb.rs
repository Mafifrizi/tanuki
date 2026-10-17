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
                if header_len <= 1024 && abs_pos + 4 + header_len <= data.len() {
                    let max_end = (abs_pos + MAX_CANDIDATE_SIZE).min(data.len());
                    let body_start = abs_pos + 4 + header_len;
                    let body_slice = &data[body_start..max_end];
                    let principal = try_parse_default_principal(body_slice);
                    let end = match measure_ccache_body_len(body_slice) {
                        Some(m_len) => body_start + m_len,
                        None => max_end,
                    };
                    let blob = data[abs_pos..end].to_vec();

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

fn skip_principal(slice: &[u8], mut cursor: usize) -> Option<usize> {
    if cursor + 12 > slice.len() {
        return None;
    }
    let _name_type = u32::from_be_bytes([
        slice[cursor],
        slice[cursor + 1],
        slice[cursor + 2],
        slice[cursor + 3],
    ]);
    let num_components = u32::from_be_bytes([
        slice[cursor + 4],
        slice[cursor + 5],
        slice[cursor + 6],
        slice[cursor + 7],
    ]) as usize;
    let realm_len = u32::from_be_bytes([
        slice[cursor + 8],
        slice[cursor + 9],
        slice[cursor + 10],
        slice[cursor + 11],
    ]) as usize;

    if num_components == 0 || num_components > 16 || realm_len == 0 || realm_len > 256 {
        return None;
    }
    cursor += 12;
    if cursor + realm_len > slice.len() {
        return None;
    }
    std::str::from_utf8(&slice[cursor..cursor + realm_len]).ok()?;
    cursor += realm_len;

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
        std::str::from_utf8(&slice[cursor..cursor + comp_len]).ok()?;
        cursor += comp_len;
    }
    Some(cursor)
}

fn measure_ccache_body_len(body_slice: &[u8]) -> Option<usize> {
    let mut cursor = skip_principal(body_slice, 0)?;
    let mut last_valid_end = cursor;

    while cursor < body_slice.len() {
        let mut next_cur = match skip_principal(body_slice, cursor) {
            Some(c) => c,
            None => break,
        };
        next_cur = match skip_principal(body_slice, next_cur) {
            Some(c) => c,
            None => break,
        };
        if next_cur + 4 > body_slice.len() {
            break;
        }
        let keylen = u16::from_be_bytes([body_slice[next_cur + 2], body_slice[next_cur + 3]]) as usize;
        next_cur += 4;
        if keylen > 4096 || next_cur + keylen + 21 > body_slice.len() {
            break;
        }
        next_cur += keylen + 21;

        if next_cur + 4 > body_slice.len() {
            break;
        }
        let num_addrs = u32::from_be_bytes([
            body_slice[next_cur],
            body_slice[next_cur + 1],
            body_slice[next_cur + 2],
            body_slice[next_cur + 3],
        ]) as usize;
        next_cur += 4;
        if num_addrs > 64 {
            break;
        }
        let mut addrs_ok = true;
        for _ in 0..num_addrs {
            if next_cur + 6 > body_slice.len() {
                addrs_ok = false;
                break;
            }
            let alen = u32::from_be_bytes([
                body_slice[next_cur + 2],
                body_slice[next_cur + 3],
                body_slice[next_cur + 4],
                body_slice[next_cur + 5],
            ]) as usize;
            next_cur += 6;
            if alen > 1024 || next_cur + alen > body_slice.len() {
                addrs_ok = false;
                break;
            }
            next_cur += alen;
        }
        if !addrs_ok {
            break;
        }

        if next_cur + 4 > body_slice.len() {
            break;
        }
        let num_authdata = u32::from_be_bytes([
            body_slice[next_cur],
            body_slice[next_cur + 1],
            body_slice[next_cur + 2],
            body_slice[next_cur + 3],
        ]) as usize;
        next_cur += 4;
        if num_authdata > 64 {
            break;
        }
        let mut ad_ok = true;
        for _ in 0..num_authdata {
            if next_cur + 6 > body_slice.len() {
                ad_ok = false;
                break;
            }
            let adlen = u32::from_be_bytes([
                body_slice[next_cur + 2],
                body_slice[next_cur + 3],
                body_slice[next_cur + 4],
                body_slice[next_cur + 5],
            ]) as usize;
            next_cur += 6;
            if adlen > 65536 || next_cur + adlen > body_slice.len() {
                ad_ok = false;
                break;
            }
            next_cur += adlen;
        }
        if !ad_ok {
            break;
        }

        if next_cur + 4 > body_slice.len() {
            break;
        }
        let tkt_len = u32::from_be_bytes([
            body_slice[next_cur],
            body_slice[next_cur + 1],
            body_slice[next_cur + 2],
            body_slice[next_cur + 3],
        ]) as usize;
        next_cur += 4;
        if tkt_len > 65536 || next_cur + tkt_len + 4 > body_slice.len() {
            break;
        }
        next_cur += tkt_len;
        let sec_tkt_len = u32::from_be_bytes([
            body_slice[next_cur],
            body_slice[next_cur + 1],
            body_slice[next_cur + 2],
            body_slice[next_cur + 3],
        ]) as usize;
        next_cur += 4;
        if sec_tkt_len > 65536 || next_cur + sec_tkt_len > body_slice.len() {
            break;
        }
        next_cur += sec_tkt_len;
        cursor = next_cur;
        last_valid_end = cursor;
    }

    Some(last_valid_end)
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
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if meta.file_type().is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Refusing to write to symlink target: {}", path.display()),
                ));
            }
        }
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
