use super::types::{enctype_name, KeytabEntry};
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum KeytabError {
    InvalidHeader,
    UnexpectedEof,
    MalformedEntry(String),
}

impl fmt::Display for KeytabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeytabError::InvalidHeader => {
                write!(f, "Invalid keytab format (expected Keytab v2 signature 0x0502)")
            }
            KeytabError::UnexpectedEof => write!(f, "Unexpected end of keytab stream"),
            KeytabError::MalformedEntry(msg) => write!(f, "Malformed keytab entry: {}", msg),
        }
    }
}

impl std::error::Error for KeytabError {}

pub fn parse_keytab_bytes(data: &[u8]) -> Result<Vec<KeytabEntry>, KeytabError> {
    if data.len() < 2 || data[0] != 0x05 || data[1] != 0x02 {
        return Err(KeytabError::InvalidHeader);
    }

    let mut entries = Vec::new();
    let mut cursor = 2;

    while cursor + 4 <= data.len() {
        let size_bytes: [u8; 4] = data[cursor..cursor + 4]
            .try_into()
            .map_err(|_| KeytabError::UnexpectedEof)?;
        let entry_size = i32::from_be_bytes(size_bytes);
        cursor += 4;

        if entry_size == 0 {
            continue;
        }

        if entry_size < 0 {
            let skip_len = (-entry_size) as usize;
            if cursor + skip_len > data.len() {
                break;
            }
            cursor += skip_len;
            continue;
        }

        let entry_len = entry_size as usize;
        if cursor + entry_len > data.len() {
            return Err(KeytabError::UnexpectedEof);
        }

        let entry_bytes = &data[cursor..cursor + entry_len];
        cursor += entry_len;

        let entry = parse_single_entry(entry_bytes)?;
        entries.push(entry);
    }

    Ok(entries)
}

fn parse_single_entry(entry: &[u8]) -> Result<KeytabEntry, KeytabError> {
    let mut offset = 0;

    if offset + 2 > entry.len() {
        return Err(KeytabError::MalformedEntry("Missing component count".into()));
    }
    let num_components = i16::from_be_bytes(
        entry[offset..offset + 2]
            .try_into()
            .map_err(|_| KeytabError::UnexpectedEof)?,
    );
    offset += 2;

    if num_components <= 0 {
        return Err(KeytabError::MalformedEntry(
            "Non-positive component count".into(),
        ));
    }

    if offset + 2 > entry.len() {
        return Err(KeytabError::MalformedEntry("Missing realm length".into()));
    }
    let realm_len = u16::from_be_bytes(
        entry[offset..offset + 2]
            .try_into()
            .map_err(|_| KeytabError::UnexpectedEof)?,
    ) as usize;
    offset += 2;

    if offset + realm_len > entry.len() {
        return Err(KeytabError::MalformedEntry("Realm bounds exceeded".into()));
    }
    let realm = String::from_utf8_lossy(&entry[offset..offset + realm_len]).into_owned();
    offset += realm_len;

    let mut components = Vec::with_capacity(num_components as usize);
    for _ in 0..num_components {
        if offset + 2 > entry.len() {
            return Err(KeytabError::MalformedEntry(
                "Missing component length".into(),
            ));
        }
        let comp_len = u16::from_be_bytes(
            entry[offset..offset + 2]
                .try_into()
                .map_err(|_| KeytabError::UnexpectedEof)?,
        ) as usize;
        offset += 2;

        if offset + comp_len > entry.len() {
            return Err(KeytabError::MalformedEntry(
                "Component bounds exceeded".into(),
            ));
        }
        let comp = String::from_utf8_lossy(&entry[offset..offset + comp_len]).into_owned();
        components.push(comp);
        offset += comp_len;
    }

    let principal = format!("{}@{}", components.join("/"), realm);

    // Header fields: name_type (4), timestamp (4), vno8 (1), keytype (2), key_len (2) = 13 bytes
    if offset + 13 > entry.len() {
        return Err(KeytabError::MalformedEntry(
            "Missing key metadata fields".into(),
        ));
    }

    let _name_type = u32::from_be_bytes(entry[offset..offset + 4].try_into().unwrap());
    offset += 4;

    let timestamp = u32::from_be_bytes(entry[offset..offset + 4].try_into().unwrap());
    offset += 4;

    let vno8 = entry[offset];
    offset += 1;

    let keytype = i16::from_be_bytes(entry[offset..offset + 2].try_into().unwrap());
    offset += 2;

    let key_len = u16::from_be_bytes(entry[offset..offset + 2].try_into().unwrap());
    offset += 2;

    let key_len_usize = key_len as usize;
    if offset + key_len_usize > entry.len() {
        return Err(KeytabError::MalformedEntry("Key data bounds exceeded".into()));
    }
    let key_slice = &entry[offset..offset + key_len_usize];
    offset += key_len_usize;

    let mut key_hex = String::with_capacity(key_len_usize * 2);
    for b in key_slice {
        use std::fmt::Write;
        let _ = write!(key_hex, "{:02x}", b);
    }

    let mut vno = vno8 as u32;
    if entry.len() >= offset + 4 {
        let vno32 = u32::from_be_bytes(entry[offset..offset + 4].try_into().unwrap());
        if vno32 != 0 {
            vno = vno32;
        }
    }

    let enc_name = enctype_name(keytype);

    Ok(KeytabEntry {
        principal,
        realm,
        components,
        vno,
        keytype,
        enctype_name: enc_name,
        key_len,
        key_hex,
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_keytab(
        components: &[&str],
        realm: &str,
        keytype: i16,
        key: &[u8],
        vno8: u8,
        vno32: u32,
    ) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&(components.len() as i16).to_be_bytes());
        entry.extend_from_slice(&(realm.len() as u16).to_be_bytes());
        entry.extend_from_slice(realm.as_bytes());
        for c in components {
            entry.extend_from_slice(&(c.len() as u16).to_be_bytes());
            entry.extend_from_slice(c.as_bytes());
        }
        entry.extend_from_slice(&1u32.to_be_bytes()); // name_type
        entry.extend_from_slice(&1700000000u32.to_be_bytes()); // timestamp
        entry.push(vno8);
        entry.extend_from_slice(&keytype.to_be_bytes());
        entry.extend_from_slice(&(key.len() as u16).to_be_bytes());
        entry.extend_from_slice(key);
        entry.extend_from_slice(&vno32.to_be_bytes());

        let mut data = vec![0x05, 0x02];
        data.extend_from_slice(&(entry.len() as i32).to_be_bytes());
        data.extend_from_slice(&entry);
        data
    }

    #[test]
    fn test_parse_valid_aes256_entry() {
        let key = vec![0xaa; 32];
        let bytes = build_test_keytab(
            &["HOST", "server01.corp.local"],
            "CORP.LOCAL",
            18,
            &key,
            3,
            3,
        );

        let entries = parse_keytab_bytes(&bytes).expect("Should parse valid keytab");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.principal, "HOST/server01.corp.local@CORP.LOCAL");
        assert_eq!(entry.realm, "CORP.LOCAL");
        assert_eq!(entry.components, vec!["HOST", "server01.corp.local"]);
        assert_eq!(entry.keytype, 18);
        assert_eq!(entry.enctype_name, "aes256-cts-hmac-sha1-96");
        assert_eq!(entry.vno, 3);
        assert_eq!(entry.key_len, 32);
        assert_eq!(entry.key_hex, "aa".repeat(32));
        assert_eq!(entry.timestamp, 1700000000);
        assert!(entry.is_modern_aes());
    }

    #[test]
    fn test_parse_32bit_kvno_override() {
        let key = vec![0x11; 16];
        let bytes = build_test_keytab(&["HTTP", "app.corp.local"], "CORP.LOCAL", 17, &key, 5, 500);

        let entries = parse_keytab_bytes(&bytes).expect("Should parse");
        assert_eq!(entries[0].vno, 500);
        assert_eq!(entries[0].enctype_name, "aes128-cts-hmac-sha1-96");
    }

    #[test]
    fn test_invalid_header_rejection() {
        let bad = vec![0x01, 0x02, 0x00, 0x00];
        assert_eq!(
            parse_keytab_bytes(&bad),
            Err(KeytabError::InvalidHeader)
        );
    }

    #[test]
    fn test_skip_deleted_negative_size_entry() {
        let mut data = vec![0x05, 0x02];
        // Deleted entry with negative size (-8)
        data.extend_from_slice(&(-8i32).to_be_bytes());
        data.extend_from_slice(&[0x00; 8]);

        // Followed by valid entry
        let key = vec![0xbb; 32];
        let valid_data = build_test_keytab(&["krbtgt", "CORP.LOCAL"], "CORP.LOCAL", 18, &key, 1, 1);
        data.extend_from_slice(&valid_data[2..]);

        let entries = parse_keytab_bytes(&data).expect("Should skip deleted hole");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].principal, "krbtgt/CORP.LOCAL@CORP.LOCAL");
    }
}
