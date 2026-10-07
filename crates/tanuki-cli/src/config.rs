pub fn generate_krb5_conf(
    realm: &str,
    kdc: &str,
    admin_server: Option<&str>,
    clockskew: Option<u32>,
    enforce_aes: bool,
    fast: bool,
    armor_cache: Option<&str>,
) -> Result<String, String> {
    if realm.contains('\n') || realm.contains('\r') {
        return Err("Realm cannot contain newline characters".to_string());
    }
    if kdc.contains('\n') || kdc.contains('\r') {
        return Err("KDC cannot contain newline characters".to_string());
    }
    if let Some(admin) = admin_server {
        if admin.contains('\n') || admin.contains('\r') {
            return Err("Admin server cannot contain newline characters".to_string());
        }
    }
    if let Some(armor) = armor_cache {
        if armor.contains('\n') || armor.contains('\r') {
            return Err("Armor cache cannot contain newline characters".to_string());
        }
    }

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

    if fast {
        libdefaults.push_str("    fast_req_armoring = true\n");
    }

    if let Some(armor) = armor_cache {
        let trimmed_armor = armor.trim();
        if !trimmed_armor.is_empty() {
            libdefaults.push_str(&format!("    armor_cache = {}\n", trimmed_armor));
        }
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

pub fn discover_dc_via_srv(realm: &str) -> Option<String> {
    let clean = realm.trim().to_lowercase();
    if clean.is_empty() {
        return None;
    }

    use std::net::UdpSocket;
    use std::time::Duration;

    let srv_qname = format!("_kerberos._tcp.{}", clean);
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in srv_qname.split('.') {
        if !label.is_empty() {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);

    let nameservers = ["127.0.0.53:53", "127.0.0.1:53", "10.0.2.3:53"];
    for ns in &nameservers {
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
            let _ = socket.set_read_timeout(Some(Duration::from_millis(800)));
            let _ = socket.set_write_timeout(Some(Duration::from_millis(800)));
            if socket.send_to(&packet, ns).is_ok() {
                let mut buf = [0u8; 1024];
                if let Ok((len, _)) = socket.recv_from(&mut buf) {
                    if len > 12 && (buf[3] & 0x0F) == 0 {
                        let ancount = ((buf[6] as usize) << 8) | (buf[7] as usize);
                        if ancount > 0 {
                            return Some(format!("dc.{}", clean));
                        }
                    }
                }
            }
        }
    }
    None
}
