use tanuki::{
    candidates_to_json, entries_to_json, escape_json, find_error_resolution,
    generate_krb5_conf, ladder_to_json, parse_keytab_bytes, parse_rbcd_security_descriptor,
    parse_windows_sid, save_candidates, scan_for_ccache_blobs, KeytabError, DECISION_LADDER,
    ERROR_DICTIONARY,
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
    entry.extend_from_slice(&1u32.to_be_bytes());
    entry.extend_from_slice(&1712000000u32.to_be_bytes());
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
fn test_keytab_zero_components() {
    let mut file_bytes = vec![0x05, 0x02];
    let entry = build_keytab_entry(&[], "CORP.LOCAL", 18, &[0x33; 32], 1, 1);
    file_bytes.extend_from_slice(&(entry.len() as i32).to_be_bytes());
    file_bytes.extend_from_slice(&entry);

    let entries = parse_keytab_bytes(&file_bytes).expect("Keytab with 0 components");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].principal, "@CORP.LOCAL");
    assert!(entries[0].components.is_empty());
}

#[test]
fn test_keytab_negative_size_i32_min_safety() {
    let mut file_bytes = vec![0x05, 0x02];
    file_bytes.extend_from_slice(&i32::MIN.to_be_bytes());
    assert_eq!(
        parse_keytab_bytes(&file_bytes),
        Err(KeytabError::UnexpectedEof)
    );
}

#[test]
fn test_keytab_truncated_hole_error() {
    let mut file_bytes = vec![0x05, 0x02];
    file_bytes.extend_from_slice(&(-100i32).to_be_bytes());
    file_bytes.extend_from_slice(&[0x00; 10]);
    assert_eq!(
        parse_keytab_bytes(&file_bytes),
        Err(KeytabError::UnexpectedEof)
    );
}

#[test]
fn test_keytab_incomplete_vno32() {
    let mut file_bytes = vec![0x05, 0x02];
    let mut entry = build_keytab_entry(&["HOST", "dc01.corp.local"], "CORP.LOCAL", 18, &[0x44; 32], 1, 1);
    // Truncate last 2 bytes of the 4-byte vno32 field
    entry.truncate(entry.len() - 2);
    file_bytes.extend_from_slice(&(entry.len() as i32).to_be_bytes());
    file_bytes.extend_from_slice(&entry);

    assert!(matches!(
        parse_keytab_bytes(&file_bytes),
        Err(KeytabError::MalformedEntry(_))
    ));
}

#[test]
fn test_kcm_blob_scanning_and_saving() {
    let temp_dir = std::env::temp_dir().join("tanuki_test_kcm");
    let _ = std::fs::remove_dir_all(&temp_dir);

    let mut mock_ldb = vec![0x99; 128];

    let mut ccache = vec![0x05, 0x04];
    ccache.extend_from_slice(&8u16.to_be_bytes());
    ccache.extend_from_slice(&[0x00; 8]);
    ccache.extend_from_slice(&1u32.to_be_bytes());
    ccache.extend_from_slice(&1u32.to_be_bytes());
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

    let saved = save_candidates(&candidates, &temp_dir, "ticket").expect("Saved");
    assert_eq!(saved.len(), 1);
    assert!(saved[0].exists());
    assert!(saved[0].to_string_lossy().contains("ticket_1.ccache"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_kcm_boundary_blob_detection() {
    let mut blob = vec![0x05, 0x04];
    blob.extend_from_slice(&0u16.to_be_bytes());
    let candidates = scan_for_ccache_blobs(&blob);
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].header_len, 0);
}

#[test]
fn test_error_dictionary_lookups() {
    assert_eq!(ERROR_DICTIONARY.len(), 15);

    let skew = find_error_resolution("KRB_AP_ERR_SKEW").expect("Found");
    assert_eq!(skew.event_id, Some(37));

    let etype = find_error_resolution("14").expect("Found by event ID");
    assert_eq!(etype.code, "KDC_ERR_ETYPE_NOSUPP");

    let preauth = find_error_resolution("PREAUTH").expect("Found by substring");
    assert_eq!(preauth.code, "KDC_ERR_PREAUTH_FAILED");

    let fast = find_error_resolution("KDC_ERR_PREAUTH_REQUIRED_FOR_FAST").expect("Found FAST");
    assert_eq!(fast.event_id, Some(93));

    let fast_num = find_error_resolution("93").expect("Found FAST by 93");
    assert_eq!(fast_num.code, "KDC_ERR_PREAUTH_REQUIRED_FOR_FAST");

    let event_4768 = find_error_resolution("4768").expect("Found by Windows Event ID 4768");
    assert_eq!(event_4768.code, "EVENT_4768");
    assert!(event_4768.telemetry.event_ids.contains(&4768));

    let hex_fail = find_error_resolution("0x18").expect("Found by hex failure code");
    assert_eq!(hex_fail.event_id, Some(24));

    assert_eq!(find_error_resolution(""), None);
    assert_eq!(find_error_resolution("   "), None);
}

#[test]
fn test_decision_ladder_structure_and_json() {
    assert_eq!(DECISION_LADDER.len(), 5);
    assert!(DECISION_LADDER[0].title.contains("LOCAL PASSIVE TRIAGE"));
    assert!(DECISION_LADDER[1].title.contains("ZERO-NOISE OPSEC"));

    let json = ladder_to_json();
    assert!(json.contains("\"rung\": 1"));
    assert!(json.contains("RUNG 1: LOCAL PASSIVE TRIAGE"));
}

#[test]
fn test_json_escaping_control_characters() {
    assert_eq!(escape_json("test\x00string"), "test\\u0000string");
    assert_eq!(escape_json("foo\x1bbar"), "foo\\u001bbar");
    assert_eq!(escape_json("tab\there\r\n"), "tab\\there\\r\\n");
    assert_eq!(escape_json("\"quoted\""), "\\\"quoted\\\"");
}

#[test]
fn test_generate_krb5_conf_fast_and_crlf_defense() {
    assert!(generate_krb5_conf("CORP.LOCAL\r\nINJECT", "10.0.0.1", None, None, false, false, None).is_err());
    assert!(generate_krb5_conf("CORP.LOCAL", "10.0.0.1\nINJECT", None, None, false, false, None).is_err());
    assert!(generate_krb5_conf("CORP.LOCAL", "10.0.0.1", Some("admin\r\n"), None, false, false, None).is_err());
    assert!(generate_krb5_conf("CORP.LOCAL", "10.0.0.1", None, None, false, false, Some("/tmp/armor\n")).is_err());

    let conf = generate_krb5_conf(
        "LAB.LOCAL",
        "192.168.56.106",
        None,
        Some(36000),
        true,
        true,
        Some("/tmp/krb5cc_armor"),
    ).expect("Valid config synthesis");

    assert!(conf.contains("default_realm = LAB.LOCAL"));
    assert!(conf.contains("clockskew = 36000"));
    assert!(conf.contains("fast_req_armoring = true"));
    assert!(conf.contains("armor_cache = /tmp/krb5cc_armor"));
    assert!(conf.contains("default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96"));
}

#[test]
fn test_parse_windows_sid_bounds() {
    let mut sid_bytes = vec![0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
    sid_bytes.extend_from_slice(&21u32.to_le_bytes());
    sid_bytes.extend_from_slice(&1000u32.to_le_bytes());
    sid_bytes.extend_from_slice(&2000u32.to_le_bytes());
    sid_bytes.extend_from_slice(&3000u32.to_le_bytes());

    let (sid_str, len) = parse_windows_sid(&sid_bytes, 0, None).expect("Valid SID");
    assert_eq!(sid_str, "S-1-5-21-1000-2000-3000");
    assert_eq!(len, 24);

    let bounded = parse_windows_sid(&sid_bytes, 0, Some(24)).expect("Bounded SID within container");
    assert_eq!(bounded.0, "S-1-5-21-1000-2000-3000");

    let under_bounded = parse_windows_sid(&sid_bytes, 0, Some(20));
    assert!(under_bounded.is_err());

    let invalid_subauth = vec![0x01, 16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
    assert!(parse_windows_sid(&invalid_subauth, 0, None).is_err());
}

#[test]
fn test_parse_rbcd_security_descriptor_parity() {
    let mut sid1 = vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
    sid1.extend_from_slice(&21u32.to_le_bytes());
    sid1.extend_from_slice(&500u32.to_le_bytes());

    let mut sid2 = vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
    sid2.extend_from_slice(&21u32.to_le_bytes());
    sid2.extend_from_slice(&501u32.to_le_bytes());

    let ace1_len = 8 + sid1.len();
    let mut ace1 = vec![0x00, 0x00];
    ace1.extend_from_slice(&(ace1_len as u16).to_le_bytes());
    ace1.extend_from_slice(&0x10000000u32.to_le_bytes());
    ace1.extend_from_slice(&sid1);

    let ace2_len = 8 + sid2.len();
    let mut ace2 = vec![0x01, 0x00];
    ace2.extend_from_slice(&(ace2_len as u16).to_le_bytes());
    ace2.extend_from_slice(&0x10000000u32.to_le_bytes());
    ace2.extend_from_slice(&sid2);

    let acl_len = 8 + ace1.len() + ace2.len();
    let mut acl = vec![0x02, 0x00];
    acl.extend_from_slice(&(acl_len as u16).to_le_bytes());
    acl.extend_from_slice(&2u16.to_le_bytes());
    acl.extend_from_slice(&0u16.to_le_bytes());
    acl.extend_from_slice(&ace1);
    acl.extend_from_slice(&ace2);

    let mut sd = vec![0x01, 0x00];
    sd.extend_from_slice(&0x0004u16.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&acl);

    let rbcd = parse_rbcd_security_descriptor(&sd).expect("Valid RBCD SD");
    assert_eq!(rbcd.ace_count, 2);
    assert_eq!(rbcd.trustee_sids, vec!["S-1-5-21-500".to_string()]);
    assert_eq!(rbcd.allowed_trustee_sids, vec!["S-1-5-21-500".to_string()]);
    assert_eq!(rbcd.denied_trustee_sids, vec!["S-1-5-21-501".to_string()]);
    assert_eq!(rbcd.aces.len(), 2);
    assert!(rbcd.aces[0].is_allowed);
    assert!(!rbcd.aces[1].is_allowed);

    let mut invalid_offset_sd = sd.clone();
    invalid_offset_sd[16..20].copy_from_slice(&10u32.to_le_bytes());
    assert!(parse_rbcd_security_descriptor(&invalid_offset_sd).is_err());
}
