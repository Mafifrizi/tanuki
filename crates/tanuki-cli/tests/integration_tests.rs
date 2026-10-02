use std::path::PathBuf;
use tanuki::{
    candidates_to_json, entries_to_json, find_error_resolution, parse_keytab_bytes,
    save_candidates, scan_for_ccache_blobs, DECISION_LADDER, ERROR_DICTIONARY,
};

fn build_keytab_entry(
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
    entry.extend_from_slice(&1712000000u32.to_be_bytes()); // timestamp
    entry.push(vno8);
    entry.extend_from_slice(&keytype.to_be_bytes());
    entry.extend_from_slice(&(key.len() as u16).to_be_bytes());
    entry.extend_from_slice(key);
    entry.extend_from_slice(&vno32.to_be_bytes());
    entry
}

#[test]
fn test_multi_entry_keytab_parsing() {
    let mut file_bytes = vec![0x05, 0x02];

    let entry1 = build_keytab_entry(
        &["HOST", "web01.corp.local"],
        "CORP.LOCAL",
        18,
        &[0x11; 32],
        2,
        2,
    );
    file_bytes.extend_from_slice(&(entry1.len() as i32).to_be_bytes());
    file_bytes.extend_from_slice(&entry1);

    let entry2 = build_keytab_entry(
        &["HTTP", "web01.corp.local"],
        "CORP.LOCAL",
        17,
        &[0x22; 16],
        2,
        2,
    );
    file_bytes.extend_from_slice(&(entry2.len() as i32).to_be_bytes());
    file_bytes.extend_from_slice(&entry2);

    let entries = parse_keytab_bytes(&file_bytes).expect("Valid multi-entry keytab");
    assert_eq!(entries.len(), 2);

    assert_eq!(entries[0].principal, "HOST/web01.corp.local@CORP.LOCAL");
    assert_eq!(entries[0].keytype, 18);
    assert_eq!(entries[0].enctype_name, "aes256-cts-hmac-sha1-96");

    assert_eq!(entries[1].principal, "HTTP/web01.corp.local@CORP.LOCAL");
    assert_eq!(entries[1].keytype, 17);
    assert_eq!(entries[1].enctype_name, "aes128-cts-hmac-sha1-96");

    let json_output = entries_to_json(&entries);
    assert!(json_output.contains("\"principal\": \"HOST/web01.corp.local@CORP.LOCAL\""));
    assert!(json_output.contains("\"aes256-cts-hmac-sha1-96\""));
}

#[test]
fn test_kcm_blob_scanning_and_saving() {
    let temp_dir = std::env::temp_dir().join("tanuki_test_kcm");
    let _ = std::fs::remove_dir_all(&temp_dir);

    let mut mock_ldb = vec![0x99; 128];

    // Embed CCACHE stream
    let mut ccache = vec![0x05, 0x04];
    ccache.extend_from_slice(&8u16.to_be_bytes()); // header_len
    ccache.extend_from_slice(&[0x00; 8]); // header body
    ccache.extend_from_slice(&1u32.to_be_bytes()); // name_type
    ccache.extend_from_slice(&1u32.to_be_bytes()); // num_components
    let realm = b"CORP.LOCAL";
    ccache.extend_from_slice(&(realm.len() as u32).to_be_bytes());
    ccache.extend_from_slice(realm);
    let comp = b"svc_backup";
    ccache.extend_from_slice(&(comp.len() as u32).to_be_bytes());
    ccache.extend_from_slice(comp);
    ccache.extend_from_slice(&[0xaa; 64]);

    mock_ldb.extend_from_slice(&ccache);
    mock_ldb.extend_from_slice(&[0x88; 64]);

    let candidates = scan_for_ccache_blobs(&mock_ldb);
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].default_principal,
        Some("svc_backup@CORP.LOCAL".to_string())
    );

    let json = candidates_to_json(&candidates);
    assert!(json.contains("svc_backup@CORP.LOCAL"));

    let saved = save_candidates(&candidates, &temp_dir, "test").expect("Saved");
    assert_eq!(saved.len(), 1);
    assert!(saved[0].exists());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_error_dictionary_lookups() {
    assert_eq!(ERROR_DICTIONARY.len(), 5);

    let skew = find_error_resolution("KRB_AP_ERR_SKEW").expect("Found");
    assert_eq!(skew.event_id, Some(37));

    let etype = find_error_resolution("14").expect("Found by event ID");
    assert_eq!(etype.code, "KDC_ERR_ETYPE_NOSUPP");

    let preauth = find_error_resolution("PREAUTH").expect("Found by substring");
    assert_eq!(preauth.code, "KDC_ERR_PREAUTH_FAILED");
}

#[test]
fn test_decision_ladder_structure() {
    assert_eq!(DECISION_LADDER.len(), 5);
    assert!(DECISION_LADDER[0].0.contains("Local Passive"));
    assert!(DECISION_LADDER[1].0.contains("OPSEC Guardrails"));
    assert!(DECISION_LADDER[2].0.contains("Machine Identity"));
}
