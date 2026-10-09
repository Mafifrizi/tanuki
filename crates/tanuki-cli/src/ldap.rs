use crate::util::escape_json;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_ENUMERATED: u8 = 0x0A;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;

pub const LDAP_REQ_BIND: u8 = 0x60;
pub const LDAP_RESP_BIND: u8 = 0x61;
pub const LDAP_REQ_UNBIND: u8 = 0x42;
pub const LDAP_REQ_SEARCH: u8 = 0x63;
pub const LDAP_RESP_SEARCH_ENTRY: u8 = 0x64;
pub const LDAP_RESP_SEARCH_DONE: u8 = 0x65;

pub const SCOPE_BASE: u8 = 0;
pub const SCOPE_ONE_LEVEL: u8 = 1;
pub const SCOPE_SUBTREE: u8 = 2;

pub const FILTER_AND: u8 = 0xA0;
pub const FILTER_OR: u8 = 0xA1;
pub const FILTER_NOT: u8 = 0xA2;
pub const FILTER_EQUALITY: u8 = 0xA3;
pub const FILTER_SUBSTRINGS: u8 = 0xA4;
pub const FILTER_GE: u8 = 0xA5;
pub const FILTER_LE: u8 = 0xA6;
pub const FILTER_PRESENT: u8 = 0x87;
pub const FILTER_EXTENSIBLE: u8 = 0xA9;

pub fn ber_encode_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = Vec::new();
    let mut temp = len;
    while temp > 0 {
        bytes.insert(0, (temp & 0xFF) as u8);
        temp >>= 8;
    }
    let mut out = vec![0x80 | (bytes.len() as u8)];
    out.extend(bytes);
    out
}

pub fn ber_encode_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(ber_encode_length(value.len()));
    out.extend_from_slice(value);
    out
}

pub fn ber_encode_int(val: i64) -> Vec<u8> {
    if val == 0 {
        return ber_encode_tlv(TAG_INTEGER, &[0x00]);
    }
    let mut bytes = Vec::new();
    let mut temp = val;
    if val > 0 {
        while temp > 0 {
            bytes.insert(0, (temp & 0xFF) as u8);
            temp >>= 8;
        }
        if (bytes[0] & 0x80) != 0 {
            bytes.insert(0, 0x00);
        }
    } else {
        while temp != -1 || bytes.first().map_or(false, |&b| (b & 0x80) == 0) {
            bytes.insert(0, (temp & 0xFF) as u8);
            temp >>= 8;
            if temp == -1 && (bytes[0] & 0x80) != 0 {
                break;
            }
        }
    }
    ber_encode_tlv(TAG_INTEGER, &bytes)
}

pub fn ber_encode_string(s: &str) -> Vec<u8> {
    ber_encode_tlv(TAG_OCTET_STRING, s.as_bytes())
}

pub fn ber_encode_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    let total_len: usize = elements.iter().map(|e| e.len()).sum();
    let mut val = Vec::with_capacity(total_len);
    for e in elements {
        val.extend_from_slice(e);
    }
    ber_encode_tlv(TAG_SEQUENCE, &val)
}

pub fn ber_decode_tlv(data: &[u8], offset: usize) -> Result<(u8, &[u8], usize), String> {
    if offset >= data.len() {
        return Err(format!("Unexpected end of BER stream at offset {}", offset));
    }
    let tag = data[offset];
    let mut curr = offset + 1;
    if curr >= data.len() {
        return Err("Truncated BER length byte".to_string());
    }
    let len_byte = data[curr];
    curr += 1;

    let length: usize = if (len_byte & 0x80) == 0 {
        len_byte as usize
    } else {
        let num_len_bytes = (len_byte & 0x7F) as usize;
        if num_len_bytes == 0 || num_len_bytes > std::mem::size_of::<usize>() || curr + num_len_bytes > data.len() {
            return Err(format!("Invalid BER multi-byte length at offset {}", curr));
        }
        let mut l: usize = 0;
        for &b in &data[curr..curr + num_len_bytes] {
            l = (l << 8) | (b as usize);
        }
        curr += num_len_bytes;
        l
    };

    let end_offset = match curr.checked_add(length) {
        Some(end) => end,
        None => return Err(format!("BER length arithmetic overflow at offset {}", curr)),
    };
    if end_offset > data.len() {
        return Err(format!(
            "BER value out of bounds: length {} > remaining {}",
            length,
            data.len().saturating_sub(curr)
        ));
    }
    let val = &data[curr..end_offset];
    Ok((tag, val, end_offset))
}

pub fn ber_decode_int(data: &[u8]) -> i64 {
    if data.is_empty() {
        return 0;
    }
    let is_neg = (data[0] & 0x80) != 0;
    if data.len() > 8 {
        return if is_neg { i64::MIN } else { i64::MAX };
    }
    let mut val: i64 = if is_neg { -1 } else { 0 };
    for &b in data {
        val = (val << 8) | (b as i64);
    }
    val
}

pub fn ber_decode_string(data: &[u8]) -> String {
    String::from_utf8(data.to_vec())
        .unwrap_or_else(|_| data.iter().map(|&b| b as char).collect())
}

pub fn build_ldap_bind_request(
    msg_id: i64,
    bind_dn: &str,
    password: Option<&str>,
    sasl_mechanism: Option<&str>,
    sasl_credentials: Option<&[u8]>,
) -> Vec<u8> {
    let version_bytes = ber_encode_int(3);
    let name_bytes = ber_encode_string(bind_dn);

    let auth_bytes = if let Some(mech) = sasl_mechanism {
        let mut sasl_elems = vec![ber_encode_string(mech)];
        if let Some(cred) = sasl_credentials {
            sasl_elems.push(ber_encode_tlv(TAG_OCTET_STRING, cred));
        }
        let mut inner = Vec::new();
        for e in sasl_elems {
            inner.extend(e);
        }
        ber_encode_tlv(0xA3, &inner)
    } else {
        let pwd = password.unwrap_or("");
        ber_encode_tlv(0x80, pwd.as_bytes())
    };

    let mut bind_req_payload = Vec::new();
    bind_req_payload.extend(version_bytes);
    bind_req_payload.extend(name_bytes);
    bind_req_payload.extend(auth_bytes);

    let bind_req_bytes = ber_encode_tlv(LDAP_REQ_BIND, &bind_req_payload);
    let msg_id_bytes = ber_encode_int(msg_id);

    ber_encode_sequence(&[msg_id_bytes, bind_req_bytes])
}

pub fn build_ldap_search_filter(attribute: &str, value: &str) -> Vec<u8> {
    if value == "*" {
        ber_encode_tlv(FILTER_PRESENT, attribute.as_bytes())
    } else {
        let mut eq_payload = ber_encode_string(attribute);
        eq_payload.extend(ber_encode_string(value));
        ber_encode_tlv(FILTER_EQUALITY, &eq_payload)
    }
}

pub fn build_ldap_search_request(
    msg_id: i64,
    base_dn: &str,
    scope: u8,
    filter_bytes: Option<&[u8]>,
    attributes: &[&str],
    size_limit: i64,
    time_limit: i64,
) -> Vec<u8> {
    let base_bytes = ber_encode_string(base_dn);
    let scope_bytes = ber_encode_tlv(TAG_ENUMERATED, &[scope]);
    let deref_bytes = ber_encode_tlv(TAG_ENUMERATED, &[0x00]); // neverDerefAliases
    let size_bytes = ber_encode_int(size_limit);
    let time_bytes = ber_encode_int(time_limit);
    let types_only_bytes = ber_encode_tlv(TAG_BOOLEAN, &[0x00]);

    let f_bytes = match filter_bytes {
        Some(fb) => fb.to_vec(),
        None => build_ldap_search_filter("objectClass", "*"),
    };

    let attr_elems: Vec<Vec<u8>> = attributes.iter().map(|&a| ber_encode_string(a)).collect();
    let attrs_bytes = ber_encode_sequence(&attr_elems);

    let mut search_payload = Vec::new();
    search_payload.extend(base_bytes);
    search_payload.extend(scope_bytes);
    search_payload.extend(deref_bytes);
    search_payload.extend(size_bytes);
    search_payload.extend(time_bytes);
    search_payload.extend(types_only_bytes);
    search_payload.extend(f_bytes);
    search_payload.extend(attrs_bytes);

    let search_req_bytes = ber_encode_tlv(LDAP_REQ_SEARCH, &search_payload);
    let msg_id_bytes = ber_encode_int(msg_id);

    ber_encode_sequence(&[msg_id_bytes, search_req_bytes])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapSearchEntry {
    pub message_id: i64,
    pub dn: String,
    pub query_category: String,
    pub attributes: Vec<(String, Vec<String>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapReport {
    pub status: String,
    pub host: String,
    pub port: u16,
    pub query_type: String,
    pub base_dn: String,
    pub count: usize,
    pub entries: Vec<LdapSearchEntry>,
    pub message: Option<String>,
    pub error: Option<String>,
}

impl LdapReport {
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str(&format!("  \"status\": \"{}\",\n", escape_json(&self.status)));
        out.push_str(&format!("  \"host\": \"{}\",\n", escape_json(&self.host)));
        out.push_str(&format!("  \"port\": {},\n", self.port));
        out.push_str(&format!("  \"query_type\": \"{}\",\n", escape_json(&self.query_type)));
        out.push_str(&format!("  \"base_dn\": \"{}\",\n", escape_json(&self.base_dn)));
        out.push_str(&format!("  \"count\": {},\n", self.count));

        if let Some(ref m) = self.message {
            out.push_str(&format!("  \"message\": \"{}\",\n", escape_json(m)));
        }
        if let Some(ref e) = self.error {
            out.push_str(&format!("  \"error\": \"{}\",\n", escape_json(e)));
        }

        out.push_str("  \"entries\": [\n");
        for (i, entry) in self.entries.iter().enumerate() {
            out.push_str("    {\n");
            out.push_str(&format!("      \"dn\": \"{}\",\n", escape_json(&entry.dn)));
            out.push_str(&format!("      \"query_category\": \"{}\",\n", escape_json(&entry.query_category)));
            out.push_str("      \"attributes\": {\n");
            for (j, (k, vals)) in entry.attributes.iter().enumerate() {
                out.push_str(&format!("        \"{}\": [", escape_json(k)));
                for (k_idx, val) in vals.iter().enumerate() {
                    out.push_str(&format!("\"{}\"", escape_json(val)));
                    if k_idx + 1 < vals.len() {
                        out.push_str(", ");
                    }
                }
                out.push(']');
                if j + 1 < entry.attributes.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str("      }\n");
            out.push_str("    }");
            if i + 1 < self.entries.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ]\n}");
        out
    }

    pub fn format_terminal(&self) -> String {
        let mut out = String::new();
        out.push_str("[TANUKI UNPRIVILEGED LDAP QUERY ENGINE]\n");
        out.push_str(&format!(
            " Target: {}:{} · Query: {} · Found: {}\n\n",
            self.host,
            self.port,
            self.query_type.to_uppercase(),
            self.count
        ));

        if self.status != "SUCCESS" {
            out.push_str(&format!("[!] LDAP Operation Status: {}\n", self.status));
            let err_msg = self.error.as_deref().or(self.message.as_deref()).unwrap_or("Unknown error");
            out.push_str(&format!("    ╰─ Details: {}\n", err_msg));
            return out;
        }

        if self.entries.is_empty() {
            out.push_str(&format!("[*] Query returned 0 matching directory objects for filter '{}'.\n", self.query_type.to_uppercase()));
            return out;
        }

        out.push_str(&format!("[+] Discovered Active Directory Objects ({} entries):\n\n", self.entries.len()));
        for (idx, e) in self.entries.iter().enumerate() {
            let is_last = idx == self.entries.len() - 1;
            let sam = e.attributes.iter().find(|(k, _)| k == "sAMAccountName")
                .and_then(|(_, v)| v.first().cloned())
                .unwrap_or_else(|| e.dn.clone());

            out.push_str(&format!("[{}] {}\n", e.query_category.to_uppercase(), sam));
            out.push_str(&format!("    ├─ DN: {}\n", e.dn));

            for (a_name, a_vals) in &e.attributes {
                if a_name != "sAMAccountName" {
                    let is_binary_attr = matches!(
                        a_name.to_ascii_lowercase().as_str(),
                        "msds-allowedtoactonbehalfofotheridentity"
                            | "msds-keycredentiallink"
                            | "objectsid"
                            | "objectguid"
                            | "usercertificate"
                    );
                    if a_name.eq_ignore_ascii_case("msds-allowedtoactonbehalfofotheridentity") {
                        out.push_str(&format!("    ├─ {} (RBCD):\n", a_name));
                        for hex_val in a_vals {
                            let mut raw_bytes = Vec::new();
                            let mut chars = hex_val.chars();
                            while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
                                if let Ok(b) = u8::from_str_radix(&format!("{}{}", c1, c2), 16) {
                                    raw_bytes.push(b);
                                }
                            }
                            if let Ok(rbcd) = crate::pac::parse_rbcd_security_descriptor(&raw_bytes) {
                                out.push_str(&format!("    │  ├─ ACE Count: {}\n", rbcd.ace_count));
                                if rbcd.allowed_trustee_sids.is_empty() {
                                    out.push_str("    │  ╰─ Allowed Trustee: None\n");
                                } else {
                                    for (s_idx, s) in rbcd.allowed_trustee_sids.iter().enumerate() {
                                        let branch = if s_idx == rbcd.allowed_trustee_sids.len() - 1 { "╰─" } else { "├─" };
                                        out.push_str(&format!("    │  {} Allowed Trustee: {}\n", branch, s));
                                    }
                                }
                            } else {
                                out.push_str(&format!("    │  ╰─ Parse Error (raw bytes: {})\n", raw_bytes.len()));
                            }
                        }
                        continue;
                    }

                    let preview = if is_binary_attr {
                        let formatted: Vec<String> = a_vals
                            .iter()
                            .map(|hex_val| {
                                let byte_len = hex_val.len() / 2;
                                let prefix = if hex_val.len() > 16 {
                                    &hex_val[..16]
                                } else {
                                    hex_val.as_str()
                                };
                                format!("<binary: {} bytes, hex: {}...>", byte_len, prefix)
                            })
                            .collect();
                        if formatted.len() > 3 {
                            format!(
                                "{}, ... (+{} more)",
                                formatted[..3].join(", "),
                                formatted.len() - 3
                            )
                        } else {
                            formatted.join(", ")
                        }
                    } else if a_vals.len() > 3 {
                        format!("{}, ... (+{} more)", a_vals[..3].join(", "), a_vals.len() - 3)
                    } else {
                        a_vals.join(", ")
                    };
                    out.push_str(&format!("    ├─ {}: {}\n", a_name, preview));
                }
            }
            if !is_last {
                out.push('\n');
            }
        }

        out
    }
}

pub fn parse_ldap_response_stream(raw_data: &[u8]) -> Vec<LdapSearchEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset < raw_data.len() {
        let (tag, seq_val, next_off) = match ber_decode_tlv(raw_data, offset) {
            Ok(res) => res,
            Err(_) => break,
        };
        offset = next_off;

        if tag != TAG_SEQUENCE {
            continue;
        }

        let mut inner_off = 0;
        let (_id_tag, id_val, n_off) = match ber_decode_tlv(seq_val, inner_off) {
            Ok(res) => res,
            Err(_) => continue,
        };
        inner_off = n_off;
        let msg_id = ber_decode_int(id_val);

        let (op_tag, op_val, _) = match ber_decode_tlv(seq_val, inner_off) {
            Ok(res) => res,
            Err(_) => continue,
        };

        if op_tag == LDAP_RESP_SEARCH_ENTRY {
            let mut e_off = 0;
            let (_dn_tag, dn_val, n_eoff) = match ber_decode_tlv(op_val, e_off) {
                Ok(res) => res,
                Err(_) => continue,
            };
            e_off = n_eoff;
            let dn = ber_decode_string(dn_val);

            let (_attrs_tag, attrs_val, _) = match ber_decode_tlv(op_val, e_off) {
                Ok(res) => res,
                Err(_) => continue,
            };

            let mut attrs_vec: Vec<(String, Vec<String>)> = Vec::new();
            let mut a_off = 0;
            while a_off < attrs_val.len() {
                let (_, attr_seq, n_aoff) = match ber_decode_tlv(attrs_val, a_off) {
                    Ok(res) => res,
                    Err(_) => break,
                };
                a_off = n_aoff;

                let mut sub_off = 0;
                let (_, type_val, n_suboff) = match ber_decode_tlv(attr_seq, sub_off) {
                    Ok(res) => res,
                    Err(_) => continue,
                };
                sub_off = n_suboff;
                let attr_name = ber_decode_string(type_val);
                let is_binary = matches!(
                    attr_name.to_ascii_lowercase().as_str(),
                    "msds-allowedtoactonbehalfofotheridentity"
                        | "msds-keycredentiallink"
                        | "objectsid"
                        | "objectguid"
                        | "usercertificate"
                );

                let (_, vals_set, _) = match ber_decode_tlv(attr_seq, sub_off) {
                    Ok(res) => res,
                    Err(_) => continue,
                };

                let mut vals_list = Vec::new();
                let mut v_off = 0;
                while v_off < vals_set.len() {
                    let (_, v_bytes, n_voff) = match ber_decode_tlv(vals_set, v_off) {
                        Ok(res) => res,
                        Err(_) => break,
                    };
                    v_off = n_voff;
                    if is_binary {
                        let hex_str: String = v_bytes.iter().map(|b| format!("{:02x}", b)).collect();
                        vals_list.push(hex_str);
                    } else {
                        vals_list.push(ber_decode_string(v_bytes));
                    }
                }

                attrs_vec.push((attr_name, vals_list));
            }

            entries.push(LdapSearchEntry {
                message_id: msg_id,
                dn,
                query_category: "ad-object".to_string(),
                attributes: attrs_vec,
            });
        }
    }

    entries
}

fn is_search_done_received(data: &[u8]) -> bool {
    let mut offset = 0;
    while offset < data.len() {
        if offset + 2 > data.len() || data[offset] != TAG_SEQUENCE {
            offset += 1;
            continue;
        }
        match ber_decode_tlv(data, offset) {
            Ok((TAG_SEQUENCE, seq_val, next_off)) => {
                let inner_off = 0;
                if let Ok((TAG_INTEGER, _, op_off)) = ber_decode_tlv(seq_val, inner_off) {
                    if op_off < seq_val.len() {
                        let op_tag = seq_val[op_off];
                        if op_tag == LDAP_RESP_SEARCH_DONE {
                            return true;
                        }
                    }
                }
                offset = next_off;
            }
            _ => break,
        }
    }
    false
}

fn get_search_done_status(data: &[u8]) -> Option<(i64, String)> {
    let mut offset = 0;
    while offset < data.len() {
        if offset + 2 > data.len() || data[offset] != TAG_SEQUENCE {
            offset += 1;
            continue;
        }
        match ber_decode_tlv(data, offset) {
            Ok((TAG_SEQUENCE, seq_val, next_off)) => {
                let inner_off = 0;
                if let Ok((TAG_INTEGER, _, op_off)) = ber_decode_tlv(seq_val, inner_off) {
                    if op_off < seq_val.len() && seq_val[op_off] == LDAP_RESP_SEARCH_DONE {
                        if let Ok((_, op_val, _)) = ber_decode_tlv(seq_val, op_off) {
                            let mut code = 0i64;
                            let mut diag = String::new();
                            if let Ok((TAG_ENUMERATED, res_bytes, inner_done_off)) = ber_decode_tlv(op_val, 0) {
                                code = ber_decode_int(res_bytes);
                                if let Ok((_, _, next_sub_off)) = ber_decode_tlv(op_val, inner_done_off) {
                                    if let Ok((_, diag_bytes, _)) = ber_decode_tlv(op_val, next_sub_off) {
                                        diag = ber_decode_string(diag_bytes).replace('\0', "").trim().to_string();
                                    }
                                }
                            }
                            return Some((code, diag));
                        }
                    }
                }
                offset = next_off;
            }
            _ => break,
        }
    }
    None
}

pub fn query_active_directory_ldap(
    host: &str,
    query_type: &str,
    base_dn: &str,
    port: u16,
    timeout_secs: u64,
) -> LdapReport {
    let timeout = Duration::from_secs(timeout_secs);
    let socket_addr = match format!("{}:{}", host, port).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(a) => a,
            None => {
                return LdapReport {
                    status: "CONNECTION_FAILED".to_string(),
                    host: host.to_string(),
                    port,
                    query_type: query_type.to_string(),
                    base_dn: base_dn.to_string(),
                    count: 0,
                    entries: Vec::new(),
                    message: None,
                    error: Some(format!("Could not resolve host '{}'", host)),
                };
            }
        },
        Err(e) => {
            return LdapReport {
                status: "CONNECTION_FAILED".to_string(),
                host: host.to_string(),
                port,
                query_type: query_type.to_string(),
                base_dn: base_dn.to_string(),
                count: 0,
                entries: Vec::new(),
                message: None,
                error: Some(e.to_string()),
            };
        }
    };

    let probe_timeout = Duration::from_millis(800);
    let mut stream = match TcpStream::connect_timeout(&socket_addr, probe_timeout) {
        Ok(s) => s,
        Err(e) => {
            return LdapReport {
                status: "CONNECTION_FAILED".to_string(),
                host: host.to_string(),
                port,
                query_type: query_type.to_string(),
                base_dn: base_dn.to_string(),
                count: 0,
                entries: Vec::new(),
                message: None,
                error: Some(format!(
                    "Port {} unreachable on host '{}' ({}). Tactical remediation: Verify network route/firewall or configure SSH port-forwarding pivot: ssh -L 8888:{}:88 user@pivot -N / ssh -L {}:{}:{} user@pivot -N",
                    port, host, e, host, port, host, port
                )),
            };
        }
    };

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    // Send Bind Request
    let bind_req = build_ldap_bind_request(1, "", None, None, None);
    if let Err(e) = stream.write_all(&bind_req) {
        return LdapReport {
            status: "CONNECTION_FAILED".to_string(),
            host: host.to_string(),
            port,
            query_type: query_type.to_string(),
            base_dn: base_dn.to_string(),
            count: 0,
            entries: Vec::new(),
            message: None,
            error: Some(format!("Failed to write bind request: {}", e)),
        };
    }

    let mut bind_buf = vec![0u8; 1024];
    let n = match stream.read(&mut bind_buf) {
        Ok(bytes_read) => bytes_read,
        Err(e) => {
            return LdapReport {
                status: "BIND_FAILED".to_string(),
                host: host.to_string(),
                port,
                query_type: query_type.to_string(),
                base_dn: base_dn.to_string(),
                count: 0,
                entries: Vec::new(),
                message: Some(format!("Read bind response failed: {}", e)),
                error: None,
            };
        }
    };

    if n == 0 {
        return LdapReport {
            status: "BIND_FAILED".to_string(),
            host: host.to_string(),
            port,
            query_type: query_type.to_string(),
            base_dn: base_dn.to_string(),
            count: 0,
            entries: Vec::new(),
            message: Some("LDAP bind failed (server closed connection)".to_string()),
            error: None,
        };
    }

    // Execute queries
    let target_queries = if query_type == "all" {
        vec!["spn", "rbcd", "shadow", "unconstrained"]
    } else {
        vec![query_type]
    };

    let mut all_entries = Vec::new();
    let mut msg_id = 2;

    for q in target_queries {
        let (filter_attr, attrs): (&str, Vec<&str>) = match q {
            "spn" => ("servicePrincipalName", vec!["sAMAccountName", "servicePrincipalName", "userAccountControl"]),
            "rbcd" => ("msDS-AllowedToActOnBehalfOfOtherIdentity", vec!["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"]),
            "shadow" => ("msDS-KeyCredentialLink", vec!["sAMAccountName", "msDS-KeyCredentialLink"]),
            "unconstrained" => ("userAccountControl", vec!["sAMAccountName", "userAccountControl"]),
            _ => ("objectClass", vec!["sAMAccountName"]),
        };

        let f_bytes = build_ldap_search_filter(filter_attr, "*");
        let search_req = build_ldap_search_request(msg_id, base_dn, SCOPE_SUBTREE, Some(&f_bytes), &attrs, 100, 10);
        msg_id += 1;

        if let Ok(_) = stream.write_all(&search_req) {
            let mut search_buf = Vec::new();
            let mut temp_chunk = [0u8; 4096];
            while let Ok(read_bytes) = stream.read(&mut temp_chunk) {
                if read_bytes == 0 {
                    break;
                }
                search_buf.extend_from_slice(&temp_chunk[..read_bytes]);
                if is_search_done_received(&search_buf) {
                    break;
                }
            }

            if let Some((err_code, diag_msg)) = get_search_done_status(&search_buf) {
                if err_code != 0 {
                    let err_str = if diag_msg.is_empty() {
                        format!("LDAP search rejected with code {}", err_code)
                    } else {
                        format!("LDAP search rejected with code {} ({})", err_code, diag_msg)
                    };
                    return LdapReport {
                        status: "SEARCH_FAILED".to_string(),
                        host: host.to_string(),
                        port,
                        query_type: query_type.to_string(),
                        base_dn: base_dn.to_string(),
                        count: 0,
                        entries: Vec::new(),
                        message: None,
                        error: Some(err_str),
                    };
                }
            }

            let mut parsed_entries = parse_ldap_response_stream(&search_buf);
            for e in &mut parsed_entries {
                e.query_category = q.to_string();
            }
            all_entries.extend(parsed_entries);
        }
    }

    LdapReport {
        status: "SUCCESS".to_string(),
        host: host.to_string(),
        port,
        query_type: query_type.to_string(),
        base_dn: base_dn.to_string(),
        count: all_entries.len(),
        entries: all_entries,
        message: None,
        error: None,
    }
}
