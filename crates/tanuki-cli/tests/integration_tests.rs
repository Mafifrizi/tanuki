use tanuki::{
    audit_enctype_kvno, blast_report_to_json, build_ldap_bind_request,
    build_ldap_extensible_filter, build_ldap_search_filter, candidates_to_json,
    classify_identity_tier, entries_to_json, escape_json, evaluate_blast_radius,
    extract_ad_account_name, find_error_resolution, format_blast_report_terminal,
    generate_ad_remediations, generate_krb5_conf, ladder_to_json, parse_keytab_bytes,
    parse_rbcd_security_descriptor, parse_windows_sid, save_candidates,
    scan_for_ccache_blobs, BlastReport, KeytabError, LdapReport, LdapSearchEntry,
    DECISION_LADDER, ERROR_DICTIONARY,
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

#[test]
fn test_build_ldap_bind_request_simple_and_anon() {
    let anon_req = build_ldap_bind_request(1, "", None, None, None);
    assert!(!anon_req.is_empty());
    assert_eq!(anon_req[0], 0x30);

    let auth_req = build_ldap_bind_request(2, "admin@CORP.LOCAL", Some("P@ssw0rd!"), None, None);
    assert!(!auth_req.is_empty());
    assert_eq!(auth_req[0], 0x30);
    assert!(auth_req.windows("admin@CORP.LOCAL".len()).any(|w| w == b"admin@CORP.LOCAL"));
    assert!(auth_req.windows("P@ssw0rd!".len()).any(|w| w == b"P@ssw0rd!"));
}

#[test]
fn test_build_ldap_extensible_filter_asreproast() {
    let eq_filter = build_ldap_search_filter("servicePrincipalName", "*");
    assert_eq!(eq_filter[0], 0x87);

    let filter = build_ldap_extensible_filter("userAccountControl", "1.2.840.113556.1.4.803", "4194304");
    assert!(!filter.is_empty());
    assert_eq!(filter[0], 0xA9);
    assert!(filter.windows("userAccountControl".len()).any(|w| w == b"userAccountControl"));
    assert!(filter.windows("1.2.840.113556.1.4.803".len()).any(|w| w == b"1.2.840.113556.1.4.803"));
    assert!(filter.windows("4194304".len()).any(|w| w == b"4194304"));
}

#[test]
fn test_ldap_report_format_terminal_asreproast_and_rbcd() {
    let mut ace1 = vec![0x00, 0x00];
    let sid1 = [0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xf4, 0x01, 0x00, 0x00];
    let ace1_len = 8 + sid1.len();
    ace1.extend_from_slice(&(ace1_len as u16).to_le_bytes());
    ace1.extend_from_slice(&0x10000000u32.to_le_bytes());
    ace1.extend_from_slice(&sid1);

    let acl_len = 8 + ace1.len();
    let mut acl = vec![0x02, 0x00];
    acl.extend_from_slice(&(acl_len as u16).to_le_bytes());
    acl.extend_from_slice(&1u16.to_le_bytes());
    acl.extend_from_slice(&0u16.to_le_bytes());
    acl.extend_from_slice(&ace1);

    let mut sd = vec![0x01, 0x00];
    sd.extend_from_slice(&0x0004u16.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&20u32.to_le_bytes());
    sd.extend_from_slice(&acl);
    let rbcd_hex: String = sd.iter().map(|b| format!("{:02x}", b)).collect();

    let report = LdapReport {
        status: "SUCCESS".to_string(),
        host: "dc01.lab.local".to_string(),
        port: 389,
        query_type: "asreproast".to_string(),
        base_dn: "DC=lab,DC=local".to_string(),
        count: 2,
        entries: vec![
            LdapSearchEntry {
                message_id: 2,
                dn: "CN=Legacy,OU=Users,DC=lab,DC=local".to_string(),
                query_category: "asreproast".to_string(),
                attributes: vec![
                    ("sAMAccountName".to_string(), vec!["legacy-nonpreauth".to_string()]),
                    ("userAccountControl".to_string(), vec!["4194816".to_string()]),
                    ("msDS-SupportedEncryptionTypes".to_string(), vec!["0".to_string()]),
                ],
            },
            LdapSearchEntry {
                message_id: 3,
                dn: "CN=SqlSvc,OU=Users,DC=lab,DC=local".to_string(),
                query_category: "rbcd".to_string(),
                attributes: vec![
                    ("sAMAccountName".to_string(), vec!["svc-sql".to_string()]),
                    ("msDS-AllowedToActOnBehalfOfOtherIdentity".to_string(), vec![rbcd_hex]),
                ],
            },
        ],
        message: None,
        error: None,
    };

    let text = report.format_terminal();
    assert!(text.contains("legacy-nonpreauth"));
    assert!(text.contains("Pre-Authentication: DISABLED"));
    assert!(text.contains("RC4-HMAC (etype 23"));
    assert!(text.contains("$krb5asrep$23$"));
    assert!(text.contains("Vulnerable to unauthenticated offline Kerberos AS-REP roasting"));

    assert!(text.contains("svc-sql"));
    assert!(text.contains("msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD):"));
    assert!(text.contains("ACE Count: 1"));
    assert!(text.contains("Allowed Trustee: S-1-5-21-500"));
}

#[test]
fn test_enctype_kvno_sync_diagnostics() {
    let temp_dir = std::env::temp_dir().join("tanuki_test_enctype");
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).unwrap();
    let kt_path = temp_dir.join("test.keytab");

    let mut file_bytes = vec![0x05, 0x02];
    let entry = build_keytab_entry(&["HOST", "web01.lab.local"], "LAB.LOCAL", 18, &[0x55; 32], 3, 3);
    file_bytes.extend_from_slice(&(entry.len() as i32).to_be_bytes());
    file_bytes.extend_from_slice(&entry);
    std::fs::write(&kt_path, &file_bytes).unwrap();

    let kt_str = kt_path.to_str().unwrap();

    let check_desync = audit_enctype_kvno(kt_str, Some(0x18), Some(5));
    assert_eq!(check_desync.status, "FAIL");
    assert!(check_desync.details.contains("KVNO desynchronization detected"));
    assert_eq!(check_desync.get_extra_int("keytab_kvno", 0), 3);
    assert_eq!(check_desync.get_extra_int("ad_kvno", 0), 5);

    let check_no_aes = audit_enctype_kvno(kt_str, Some(0x0), Some(3));
    assert_eq!(check_no_aes.status, "WARN");
    assert!(check_no_aes.details.contains("lacks AES in msDS-SupportedEncryptionTypes"));

    let check_both = audit_enctype_kvno(kt_str, Some(0x0), Some(5));
    assert_eq!(check_both.status, "FAIL");
    assert!(check_both.details.contains("KVNO desynchronization detected"));
    assert!(check_both.details.contains("lacks AES in msDS-SupportedEncryptionTypes"));

    let check_sync = audit_enctype_kvno(kt_str, Some(0x18), Some(3));
    assert_eq!(check_sync.status, "PASS");
    assert!(check_sync.details.contains("synchronized with Active Directory"));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_blast_tier_classification_and_radius_rust() {
    let t0 = classify_identity_tier("admin@LAB.LOCAL", None, None, &[512], &[], false, false);
    assert_eq!(t0.tier, 0);
    assert_eq!(t0.severity, "CRITICAL");
    assert!(t0.is_critical);
    assert!(t0.base_score >= 90);

    let t1 = classify_identity_tier("svc@LAB.LOCAL", None, None, &[549], &[], false, false);
    assert_eq!(t1.tier, 1);
    assert_eq!(t1.severity, "HIGH");
    assert!(!t1.is_critical);

    let t2 = classify_identity_tier("user@LAB.LOCAL", None, Some(513), &[513], &[], false, false);
    assert_eq!(t2.tier, 2);
    assert_eq!(t2.severity, "LOW");
    assert_eq!(t2.base_score, 20);

    let (score, severity, paths) = evaluate_blast_radius(
        &t1,
        &["TRUSTED_FOR_DELEGATION".to_string()],
        &["HTTP/tanuki-app.lab.local".to_string()],
        &["tanuki-svc".to_string()],
    );
    assert!(score >= 85);
    assert_eq!(severity, "CRITICAL");
    assert!(!paths.is_empty());
}

#[test]
fn test_blast_remediations_and_json_parity_rust() {
    let t1 = classify_identity_tier("tanuki-nhi@LAB.LOCAL", None, None, &[], &[], true, false);
    let recipes = generate_ad_remediations(
        "tanuki-nhi@LAB.LOCAL",
        &t1,
        &[],
        &["tanuki-svc".to_string()],
        &["HTTP/tanuki-app.lab.local".to_string()],
    );
    assert!(!recipes.is_empty());
    assert!(recipes.iter().any(|r| r.category == "ENCRYPTION_HARDENING" && r.powershell.contains("AES128,AES256")));
    assert!(recipes.iter().any(|r| r.category == "DELEGATION_HARDENING" && r.powershell.contains("msDS-AllowedToActOnBehalfOfOtherIdentity")));

    // Verify account extraction on SPN vs user
    assert_eq!(extract_ad_account_name("HTTP/tanuki-app.lab.local@LAB.LOCAL"), "tanuki-app");
    assert_eq!(extract_ad_account_name("cifs/DC01.lab.local@LAB.LOCAL"), "DC01");
    assert_eq!(extract_ad_account_name("tanuki-nhi@LAB.LOCAL"), "tanuki-nhi");

    let spn_recipes = generate_ad_remediations(
        "HTTP/tanuki-app.lab.local@LAB.LOCAL",
        &t1,
        &[],
        &["tanuki-svc".to_string()],
        &["HTTP/tanuki-app.lab.local".to_string()],
    );
    assert!(spn_recipes.iter().any(|r| r.category == "ENCRYPTION_HARDENING" && r.powershell.contains("tanuki-app") && !r.powershell.contains("\"HTTP\"")));
    assert!(spn_recipes.iter().any(|r| r.category == "CREDENTIAL_MAINTENANCE" && r.powershell.contains("-mapuser tanuki-app")));

    let report = BlastReport {
        principal: "tanuki-nhi@LAB.LOCAL".to_string(),
        user_sid: "S-1-5-21-1108".to_string(),
        tier_info: t1,
        blast_score: 70,
        severity: "HIGH".to_string(),
        delegation_flags: vec![],
        accessible_spns: vec!["HTTP/tanuki-app.lab.local".to_string()],
        lateral_paths: vec![],
        remediation_recipes: recipes,
    };

    let json_text = blast_report_to_json(&report);
    assert!(json_text.contains("\"operation\": \"BLAST_RADIUS_ANALYSIS\""));
    assert!(json_text.contains("\"event_id\": 4769"));
    assert!(json_text.contains("\"tier\": 1"));

    let terminal_text = format_blast_report_terminal(&report);
    assert!(terminal_text.contains("TANUKI PRIVILEGE TIERING & BLAST RADIUS ENGINE"));
    assert!(!terminal_text.contains('\u{2014}'));
}

#[test]
fn test_security_audit_rust_regressions() {
    for bad in ["CORP=LOCAL", "CORP{LOCAL}", "CORP[LOCAL]", "CORP;LOCAL", "CORP#LOCAL", "CORP LOCAL"] {
        assert!(generate_krb5_conf(bad, "10.0.0.1", None, None, false, false, None).is_err());
    }
    assert!(generate_krb5_conf("CORP.LOCAL", "10.0.0.1;evil=1", None, None, false, false, None).is_err());

    let mut pac_blob = Vec::new();
    pac_blob.extend_from_slice(&1u32.to_le_bytes());
    pac_blob.extend_from_slice(&0u32.to_le_bytes());
    pac_blob.extend_from_slice(&10u32.to_le_bytes());
    pac_blob.extend_from_slice(&8u32.to_le_bytes());
    pac_blob.extend_from_slice(&((1u64 << 32) + 24).to_le_bytes());
    pac_blob.extend_from_slice(&[0u8; 32]);
    let pac_res = tanuki::pac::parse_pac_bytes(&pac_blob);
    assert!(pac_res.is_err());

    let mut krb_err = vec![0x7E, 0x28, 0x30, 0x26];
    krb_err.extend_from_slice(b"\xa1\x11\x18\x0f20200101000000Z");
    krb_err.extend_from_slice(b"\xa4\x11\x18\x0f20261017120000Z");
    let stime = tanuki::protocol::kerberos::parse_krb_error_stime(&krb_err).expect("Parsed stime");
    assert_eq!(stime, 1792238400);
}




