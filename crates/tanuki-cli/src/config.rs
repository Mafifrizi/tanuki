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

fn parse_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_offset = offset;
    let mut visited = 0;
    while visited < 64 {
        if offset >= data.len() {
            return None;
        }
        let len = data[offset] as usize;
        if len == 0 {
            offset += 1;
            if !jumped {
                next_offset = offset;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
            offset += 2;
            if !jumped {
                next_offset = offset;
                jumped = true;
            }
            offset = ptr;
            visited += 1;
        } else {
            offset += 1;
            if offset + len > data.len() {
                return None;
            }
            let label = String::from_utf8_lossy(&data[offset..offset + len]).to_string();
            labels.push(label);
            offset += len;
            visited += 1;
        }
    }
    if labels.is_empty() {
        None
    } else {
        Some((labels.join("."), next_offset))
    }
}

pub fn discover_dc_via_srv(realm: &str) -> Option<String> {
    let clean = realm.trim().to_lowercase();
    if clean.is_empty() {
        return None;
    }

    use std::net::UdpSocket;
    use std::time::Duration;

    let srv_qnames = [
        format!("_kerberos._tcp.{}", clean),
        format!("_ldap._tcp.{}", clean),
    ];

    let nameservers = ["127.0.0.53:53", "127.0.0.1:53", "10.0.2.3:53", "192.168.56.1:53"];

    for srv_qname in &srv_qnames {
        let mut txid = [0u8; 2];
        crate::util::fill_dynamic_entropy(&mut txid);
        let mut packet = Vec::new();
        packet.extend_from_slice(&[txid[0], txid[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in srv_qname.split('.') {
            if !label.is_empty() {
                packet.push(label.len() as u8);
                packet.extend_from_slice(label.as_bytes());
            }
        }
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);

        for ns in &nameservers {
            if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
                let _ = socket.set_read_timeout(Some(Duration::from_millis(800)));
                let _ = socket.set_write_timeout(Some(Duration::from_millis(800)));
                if socket.send_to(&packet, ns).is_ok() {
                    let mut buf = [0u8; 2048];
                    if let Ok((len, _)) = socket.recv_from(&mut buf) {
                        if len > 12 && buf[0] == txid[0] && buf[1] == txid[1] && (buf[2] & 0x80) != 0 && (buf[3] & 0x0F) == 0 {
                            let qdcount = ((buf[4] as usize) << 8) | (buf[5] as usize);
                            let ancount = ((buf[6] as usize) << 8) | (buf[7] as usize);
                            if ancount > 0 {
                                let mut offset = 12;
                                for _ in 0..qdcount {
                                    if let Some((_, next_off)) = parse_dns_name(&buf[..len], offset) {
                                        offset = next_off + 4;
                                    } else {
                                        break;
                                    }
                                }
                                for _ in 0..ancount {
                                    if let Some((_, next_off)) = parse_dns_name(&buf[..len], offset) {
                                        if next_off + 10 <= len {
                                            let rtype = ((buf[next_off] as u16) << 8) | (buf[next_off + 1] as u16);
                                            let rdlength = ((buf[next_off + 8] as usize) << 8) | (buf[next_off + 9] as usize);
                                            let rdata_start = next_off + 10;
                                            if rtype == 33 && rdlength >= 6 && rdata_start + 6 < len {
                                                if let Some((target, _)) = parse_dns_name(&buf[..len], rdata_start + 6) {
                                                    let trimmed_target = target.trim_end_matches('.');
                                                    if !trimmed_target.is_empty() {
                                                        return Some(trimmed_target.to_string());
                                                    }
                                                }
                                            }
                                            if rdata_start + rdlength <= len {
                                                offset = rdata_start + rdlength;
                                                continue;
                                            }
                                        }
                                    }
                                    break;
                                }
                                return Some(format!("dc.{}", clean));
                            }
                        }
                    }
                }
            }
        }
    }
    None
}
