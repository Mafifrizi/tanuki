pub fn generate_krb5_conf(
    realm: &str,
    kdc: &str,
    admin_server: Option<&str>,
) -> Result<String, String> {
    let clean_realm = realm.trim().to_uppercase();
    if clean_realm.is_empty() {
        return Err("Realm cannot be empty".to_string());
    }
    let kdc_target = kdc.trim();
    if kdc_target.is_empty() {
        return Err("KDC cannot be empty".to_string());
    }

    let domain = clean_realm.to_lowercase();
    let admin_target = admin_server.map(|s| s.trim()).unwrap_or(kdc_target);

    let content = format!(
        "[libdefaults]\n    default_realm = {}\n    dns_lookup_realm = false\n    dns_lookup_kdc = false\n    ticket_lifetime = 24h\n    renew_lifetime = 7d\n    forwardable = true\n\n[realms]\n    {} = {{\n        kdc = {}\n        admin_server = {}\n    }}\n\n[domain_realm]\n    .{} = {}\n    {} = {}\n",
        clean_realm, clean_realm, kdc_target, admin_target, domain, clean_realm, domain, clean_realm
    );

    Ok(content)
}
