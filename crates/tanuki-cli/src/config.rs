pub fn generate_krb5_conf(
    realm: &str,
    kdc: &str,
    admin_server: Option<&str>,
    clockskew: Option<u32>,
    enforce_aes: bool,
) -> Result<String, String> {
    let clean_realm = realm.trim().to_uppercase();
    if clean_realm.is_empty() {
        return Err("Realm cannot be empty".to_string());
    }
    let kdc_raw = kdc.trim();
    if kdc_raw.is_empty() {
        return Err("KDC cannot be empty".to_string());
    }

    let mut kdc_candidates: Vec<&str> = Vec::new();
    for part in kdc_raw.split(',') {
        let trimmed = part.trim();
        if !trimmed.is_empty() && !kdc_candidates.contains(&trimmed) {
            kdc_candidates.push(trimmed);
        }
    }
    if kdc_candidates.is_empty() {
        return Err("KDC cannot be empty".to_string());
    }

    let domain = clean_realm.to_lowercase();
    let admin_target = admin_server.map(|s| s.trim()).unwrap_or(kdc_candidates[0]);

    let mut libdefaults = String::from(
        "[libdefaults]\n    default_realm = ",
    );
    libdefaults.push_str(&clean_realm);
    libdefaults.push_str("\n    dns_lookup_realm = false\n    dns_lookup_kdc = false\n    rdns = false\n    udp_preference_limit = 0\n    ticket_lifetime = 24h\n    renew_lifetime = 7d\n    forwardable = true\n");

    if let Some(skew) = clockskew {
        libdefaults.push_str(&format!("    clockskew = {}\n", skew));
    }

    if enforce_aes {
        libdefaults.push_str("    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n");
        libdefaults.push_str("    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n");
    }

    let mut kdc_lines = String::new();
    for k in &kdc_candidates {
        kdc_lines.push_str(&format!("        kdc = {}\n", k));
    }

    let content = format!(
        "{}\n[realms]\n    {} = {{\n{}        admin_server = {}\n    }}\n\n[domain_realm]\n    .{} = {}\n    {} = {}\n",
        libdefaults, clean_realm, kdc_lines, admin_target, domain, clean_realm, domain, clean_realm
    );

    Ok(content)
}
