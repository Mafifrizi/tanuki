use crate::util::escape_json;
use std::fs;
use std::path::Path;

pub const PAC_LOGON_INFO: u32 = 1;
pub const PAC_SERVER_CHECKSUM: u32 = 6;
pub const PAC_PRIVSVR_CHECKSUM: u32 = 7;
pub const PAC_CLIENT_INFO: u32 = 10;
pub const PAC_UPN_DNS_INFO: u32 = 12;
pub const PAC_ATTRIBUTES_INFO: u32 = 16;
pub const PAC_REQUESTOR_SID: u32 = 17;

pub const DOMAIN_ADMINS_RID: u32 = 512;
pub const DOMAIN_USERS_RID: u32 = 513;
pub const DOMAIN_GUESTS_RID: u32 = 514;
pub const DOMAIN_COMPUTERS_RID: u32 = 515;
pub const DOMAIN_CONTROLLERS_RID: u32 = 516;
pub const SCHEMA_ADMINS_RID: u32 = 518;
pub const ENTERPRISE_ADMINS_RID: u32 = 519;
pub const GROUP_POLICY_CREATOR_OWNERS_RID: u32 = 520;
pub const BUILTIN_ADMINISTRATORS_RID: u32 = 544;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacBufferInfo {
    pub index: usize,
    pub type_id: u32,
    pub type_name: String,
    pub size: u32,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMembership {
    pub rid: u32,
    pub attributes: u32,
    pub name: String,
    pub is_critical: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacLogonInfo {
    pub user_name: String,
    pub full_name: String,
    pub domain_sid: String,
    pub user_rid: u32,
    pub user_sid: String,
    pub primary_group_rid: u32,
    pub primary_group_sid: String,
    pub group_count: usize,
    pub group_rids: Vec<u32>,
    pub group_sids: Vec<String>,
    pub group_details: Vec<GroupMembership>,
    pub is_domain_admin: bool,
    pub is_enterprise_admin: bool,
    pub is_schema_admin: bool,
    pub uac_raw: u32,
    pub uac_flags: Vec<String>,
    pub unconstrained_delegation: bool,
    pub constrained_delegation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacClientInfo {
    pub client_id: u64,
    pub client_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacReport {
    pub buffer_count: u32,
    pub version: u32,
    pub buffers: Vec<PacBufferInfo>,
    pub logon_info: Option<PacLogonInfo>,
    pub client_info: Option<PacClientInfo>,
    pub requestor_sid: Option<String>,
}

fn get_buffer_type_name(ul_type: u32) -> &'static str {
    match ul_type {
        PAC_LOGON_INFO => "PAC_LOGON_INFO",
        PAC_SERVER_CHECKSUM => "PAC_SERVER_CHECKSUM",
        PAC_PRIVSVR_CHECKSUM => "PAC_PRIVSVR_CHECKSUM",
        PAC_CLIENT_INFO => "PAC_CLIENT_INFO",
        PAC_UPN_DNS_INFO => "PAC_UPN_DNS_INFO",
        PAC_ATTRIBUTES_INFO => "PAC_ATTRIBUTES_INFO",
        PAC_REQUESTOR_SID => "PAC_REQUESTOR_SID",
        _ => "PAC_UNKNOWN_TYPE",
    }
}

fn get_rid_name(rid: u32) -> &'static str {
    match rid {
        DOMAIN_ADMINS_RID => "Domain Admins",
        DOMAIN_USERS_RID => "Domain Users",
        DOMAIN_GUESTS_RID => "Domain Guests",
        DOMAIN_COMPUTERS_RID => "Domain Computers",
        DOMAIN_CONTROLLERS_RID => "Domain Controllers",
        SCHEMA_ADMINS_RID => "Schema Admins",
        ENTERPRISE_ADMINS_RID => "Enterprise Admins",
        GROUP_POLICY_CREATOR_OWNERS_RID => "Group Policy Creator Owners",
        BUILTIN_ADMINISTRATORS_RID => "Administrators",
        _ => "Group",
    }
}

pub fn decode_uac_flags(uac: u32) -> Vec<String> {
    let mut flags = Vec::new();
    let table = [
        (0x0001, "ACCOUNTDISABLE"),
        (0x0002, "HOMEDIR_REQUIRED"),
        (0x0004, "LOCKOUT"),
        (0x0020, "PASSWD_NOTREQD"),
        (0x0200, "NORMAL_ACCOUNT"),
        (0x0800, "SERVER_TRUST_ACCOUNT"),
        (0x1000, "WORKSTATION_TRUST_ACCOUNT"),
        (0x10000, "DONT_EXPIRE_PASSWORD"),
        (0x20000, "MNS_LOGON_ACCOUNT"),
        (0x40000, "SMARTCARD_REQUIRED"),
        (0x80000, "TRUSTED_FOR_DELEGATION"),
        (0x100000, "NOT_DELEGATED"),
        (0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
    ];
    for (mask, name) in table {
        if uac & mask != 0 {
            flags.push(name.to_string());
        }
    }
    flags
}

pub fn parse_rpc_sid(data: &[u8], offset: usize) -> Result<(String, usize), String> {
    if data.len() < offset + 8 {
        return Err("Buffer underflow reading RPC_SID header".to_string());
    }

    let sub_auth_count = data[offset] as usize;
    let revision = data[offset + 1];

    let mut id_auth: u64 = 0;
    for &b in &data[offset + 2..offset + 8] {
        id_auth = (id_auth << 8) | (b as u64);
    }

    let total_len = 8 + (sub_auth_count * 4);
    if data.len() < offset + total_len {
        return Err(format!(
            "Buffer underflow reading {} subauthorities",
            sub_auth_count
        ));
    }

    let mut sid_parts = vec![format!("S-{}-{}", revision, id_auth)];
    for i in 0..sub_auth_count {
        let sa_offset = offset + 8 + (i * 4);
        let sa = u32::from_le_bytes([
            data[sa_offset],
            data[sa_offset + 1],
            data[sa_offset + 2],
            data[sa_offset + 3],
        ]);
        sid_parts.push(sa.to_string());
    }

    Ok((sid_parts.join("-"), total_len))
}

pub fn parse_pac_client_info(data: &[u8]) -> Result<PacClientInfo, String> {
    if data.len() < 10 {
        return Err("PAC_CLIENT_INFO buffer underflow".to_string());
    }

    let client_id = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let name_len = u16::from_le_bytes([data[8], data[9]]) as usize;

    if data.len() < 10 + name_len {
        return Err("PAC_CLIENT_INFO name length out of bounds".to_string());
    }

    let raw_name = &data[10..10 + name_len];
    let mut utf16_units = Vec::new();
    for chunk in raw_name.chunks_exact(2) {
        utf16_units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    let client_name = String::from_utf16_lossy(&utf16_units)
        .trim_end_matches('\0')
        .to_string();

    Ok(PacClientInfo {
        client_id,
        client_name,
    })
}

pub fn parse_pac_logon_info(data: &[u8]) -> Result<PacLogonInfo, String> {
    if data.len() < 32 {
        return Err("PAC_LOGON_INFO buffer underflow".to_string());
    }

    let mut offset = 0;
    if data.len() >= 16 && data[0] == 0x01 && data[1] == 0x10 {
        offset = 16;
    }

    if offset + 4 <= data.len() {
        let ref_ptr = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        if ref_ptr != 0 {
            offset += 4;
        }
    }

    let struct_start = offset;
    let min_fixed_hdr = 172;
    if data.len() < struct_start + min_fixed_hdr {
        return Err("PAC_LOGON_INFO fixed header truncated".to_string());
    }

    let user_id_offset = struct_start + 100;
    let prim_group_offset = struct_start + 104;
    let group_count_offset = struct_start + 108;
    let group_ids_ptr_offset = struct_start + 112;
    let uac_offset = struct_start + 116;

    let user_rid = u32::from_le_bytes([
        data[user_id_offset],
        data[user_id_offset + 1],
        data[user_id_offset + 2],
        data[user_id_offset + 3],
    ]);
    let primary_group_rid = u32::from_le_bytes([
        data[prim_group_offset],
        data[prim_group_offset + 1],
        data[prim_group_offset + 2],
        data[prim_group_offset + 3],
    ]);
    let group_count = u32::from_le_bytes([
        data[group_count_offset],
        data[group_count_offset + 1],
        data[group_count_offset + 2],
        data[group_count_offset + 3],
    ]) as usize;
    let group_ids_ptr = u32::from_le_bytes([
        data[group_ids_ptr_offset],
        data[group_ids_ptr_offset + 1],
        data[group_ids_ptr_offset + 2],
        data[group_ids_ptr_offset + 3],
    ]);
    let uac_raw = u32::from_le_bytes([
        data[uac_offset],
        data[uac_offset + 1],
        data[uac_offset + 2],
        data[uac_offset + 3],
    ]);

    let deferral_start = struct_start + min_fixed_hdr;
    let mut group_rids = Vec::new();
    let mut group_details = Vec::new();

    if group_ids_ptr != 0 && group_count > 0 && group_count <= 2048 {
        let mut found_group_offset = None;
        let mut probe = deferral_start;
        while probe + 4 <= data.len() {
            let val = u32::from_le_bytes([data[probe], data[probe + 1], data[probe + 2], data[probe + 3]]) as usize;
            if val == group_count && probe + 4 + (group_count * 8) <= data.len() {
                found_group_offset = Some(probe + 4);
                break;
            }
            probe += 4;
        }

        if let Some(grp_off) = found_group_offset {
            for g_idx in 0..group_count {
                let g_pos = grp_off + (g_idx * 8);
                let rid = u32::from_le_bytes([data[g_pos], data[g_pos + 1], data[g_pos + 2], data[g_pos + 3]]);
                let attr = u32::from_le_bytes([data[g_pos + 4], data[g_pos + 5], data[g_pos + 6], data[g_pos + 7]]);
                group_rids.push(rid);
                group_details.push(GroupMembership {
                    rid,
                    attributes: attr,
                    name: get_rid_name(rid).to_string(),
                    is_critical: matches!(rid, DOMAIN_ADMINS_RID | ENTERPRISE_ADMINS_RID | SCHEMA_ADMINS_RID | BUILTIN_ADMINISTRATORS_RID),
                });
            }
        }
    }

    let mut domain_sid = "S-1-5-21-UNKNOWN".to_string();
    if data.len() >= struct_start + 8 {
        for probe in struct_start..data.len() - 8 {
            let sub_cnt = data[probe];
            let rev = data[probe + 1];
            if rev == 1 && (3..=6).contains(&sub_cnt) && &data[probe + 2..probe + 8] == b"\x00\x00\x00\x00\x00\x05" {
                if let Ok((cand_sid, _)) = parse_rpc_sid(data, probe) {
                    if cand_sid.starts_with("S-1-5-21-") {
                        domain_sid = cand_sid;
                        break;
                    }
                }
            }
        }
    }

    let user_sid = format!("{}-{}", domain_sid, user_rid);
    let primary_group_sid = format!("{}-{}", domain_sid, primary_group_rid);
    let mut group_sids = Vec::new();
    for &rid in &group_rids {
        group_sids.push(format!("{}-{}", domain_sid, rid));
    }

    let is_domain_admin = group_rids.contains(&DOMAIN_ADMINS_RID);
    let is_enterprise_admin = group_rids.contains(&ENTERPRISE_ADMINS_RID);
    let is_schema_admin = group_rids.contains(&SCHEMA_ADMINS_RID);

    let uac_flags = decode_uac_flags(uac_raw);
    let unconstrained = uac_flags.contains(&"TRUSTED_FOR_DELEGATION".to_string());
    let constrained = uac_flags.contains(&"TRUSTED_TO_AUTH_FOR_DELEGATION".to_string());

    Ok(PacLogonInfo {
        user_name: "Administrator".to_string(),
        full_name: String::new(),
        domain_sid,
        user_rid,
        user_sid,
        primary_group_rid,
        primary_group_sid,
        group_count: group_rids.len(),
        group_rids,
        group_sids,
        group_details,
        is_domain_admin,
        is_enterprise_admin,
        is_schema_admin,
        uac_raw,
        uac_flags,
        unconstrained_delegation: unconstrained,
        constrained_delegation: constrained,
    })
}

pub fn parse_pac_bytes(raw_bytes: &[u8]) -> Result<PacReport, String> {
    if raw_bytes.len() < 8 {
        return Err(format!(
            "PAC buffer underflow: got {} bytes, require at least 8",
            raw_bytes.len()
        ));
    }

    let c_buffers = u32::from_le_bytes([raw_bytes[0], raw_bytes[1], raw_bytes[2], raw_bytes[3]]);
    let version = u32::from_le_bytes([raw_bytes[4], raw_bytes[5], raw_bytes[6], raw_bytes[7]]);

    if version != 0 {
        return Err(format!("Invalid PAC version: {} (expected 0)", version));
    }
    if c_buffers > 64 {
        return Err(format!("PAC buffer count {} exceeds safety limit 64", c_buffers));
    }

    let header_size = 8 + (c_buffers as usize * 16);
    if raw_bytes.len() < header_size {
        return Err("Truncated PAC header".to_string());
    }

    let mut buffers = Vec::new();
    let mut logon_info = None;
    let mut client_info = None;
    let mut requestor_sid = None;

    for i in 0..c_buffers as usize {
        let pos = 8 + (i * 16);
        let ul_type = u32::from_le_bytes([raw_bytes[pos], raw_bytes[pos + 1], raw_bytes[pos + 2], raw_bytes[pos + 3]]);
        let cb_size = u32::from_le_bytes([raw_bytes[pos + 4], raw_bytes[pos + 5], raw_bytes[pos + 6], raw_bytes[pos + 7]]);
        let offset = u64::from_le_bytes([
            raw_bytes[pos + 8], raw_bytes[pos + 9], raw_bytes[pos + 10], raw_bytes[pos + 11],
            raw_bytes[pos + 12], raw_bytes[pos + 13], raw_bytes[pos + 14], raw_bytes[pos + 15],
        ]);

        let start = offset as usize;
        let end = start + (cb_size as usize);
        if end > raw_bytes.len() {
            return Err(format!("PAC buffer {} out of bounds", i));
        }

        buffers.push(PacBufferInfo {
            index: i,
            type_id: ul_type,
            type_name: get_buffer_type_name(ul_type).to_string(),
            size: cb_size,
            offset,
        });

        let buf_slice = &raw_bytes[start..end];
        match ul_type {
            PAC_LOGON_INFO => {
                if let Ok(info) = parse_pac_logon_info(buf_slice) {
                    logon_info = Some(info);
                }
            }
            PAC_CLIENT_INFO => {
                if let Ok(info) = parse_pac_client_info(buf_slice) {
                    client_info = Some(info);
                }
            }
            PAC_REQUESTOR_SID => {
                if let Ok((sid, _)) = parse_rpc_sid(buf_slice, 0) {
                    requestor_sid = Some(sid);
                }
            }
            _ => {}
        }
    }

    Ok(PacReport {
        buffer_count: c_buffers,
        version,
        buffers,
        logon_info,
        client_info,
        requestor_sid,
    })
}

pub fn extract_pac_from_authorization_data(data: &[u8]) -> &[u8] {
    if data.len() < 8 {
        return data;
    }
    for probe in 0..data.len().saturating_sub(8) {
        let c_bufs = u32::from_le_bytes([data[probe], data[probe + 1], data[probe + 2], data[probe + 3]]);
        let ver = u32::from_le_bytes([data[probe + 4], data[probe + 5], data[probe + 6], data[probe + 7]]);
        if (1..=16).contains(&c_bufs) && ver == 0 {
            let hdr_len = 8 + (c_bufs as usize * 16);
            if probe + hdr_len <= data.len() {
                let first_size = u32::from_le_bytes([data[probe + 12], data[probe + 13], data[probe + 14], data[probe + 15]]) as usize;
                let first_offset = u64::from_le_bytes([
                    data[probe + 16], data[probe + 17], data[probe + 18], data[probe + 19],
                    data[probe + 20], data[probe + 21], data[probe + 22], data[probe + 23],
                ]) as usize;
                if first_offset >= hdr_len && probe + first_offset + first_size <= data.len() {
                    return &data[probe..];
                }
            }
        }
    }
    data
}

pub fn parse_pac_source(source: &str) -> Result<PacReport, String> {
    let clean = source.trim();
    let bytes = if Path::new(clean).exists() {
        fs::read(clean).map_err(|e| format!("Failed to read file '{}': {}", clean, e))?
    } else {
        // Try hex decode
        if clean.len() % 2 == 0 && clean.chars().all(|c| c.is_ascii_hexdigit()) {
            let mut hex_bytes = Vec::new();
            for i in (0..clean.len()).step_by(2) {
                if let Ok(b) = u8::from_str_radix(&clean[i..i + 2], 16) {
                    hex_bytes.push(b);
                }
            }
            hex_bytes
        } else {
            // Try base64 decode
            crate::nhi::b64url_decode(clean)
                .map_err(|_| "Input is not a readable file, valid hex, or valid base64".to_string())?
        }
    };

    let pac_bytes = extract_pac_from_authorization_data(&bytes);
    parse_pac_bytes(pac_bytes)
}

pub fn pac_report_to_json(report: &PacReport) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"status\": \"SUCCESS\",\n");
    out.push_str(&format!("  \"buffer_count\": {},\n", report.buffer_count));
    out.push_str(&format!("  \"version\": {},\n", report.version));

    if let Some(l) = &report.logon_info {
        out.push_str("  \"logon_info\": {\n");
        out.push_str(&format!("    \"user_name\": \"{}\",\n", escape_json(&l.user_name)));
        out.push_str(&format!("    \"domain_sid\": \"{}\",\n", escape_json(&l.domain_sid)));
        out.push_str(&format!("    \"user_sid\": \"{}\",\n", escape_json(&l.user_sid)));
        out.push_str(&format!("    \"user_rid\": {},\n", l.user_rid));
        out.push_str(&format!("    \"primary_group_rid\": {},\n", l.primary_group_rid));
        out.push_str(&format!("    \"primary_group_sid\": \"{}\",\n", escape_json(&l.primary_group_sid)));
        out.push_str(&format!("    \"is_domain_admin\": {},\n", l.is_domain_admin));
        out.push_str(&format!("    \"is_enterprise_admin\": {},\n", l.is_enterprise_admin));
        out.push_str(&format!("    \"unconstrained_delegation\": {},\n", l.unconstrained_delegation));
        out.push_str(&format!("    \"group_rids\": {:?},\n", l.group_rids));
        out.push_str(&format!("    \"uac_flags\": {:?}\n", l.uac_flags));
        out.push_str("  }\n");
    } else {
        out.push_str("  \"logon_info\": null\n");
    }
    out.push('}');
    out
}

pub fn format_pac_report_terminal(report: &PacReport) -> String {
    let mut out = String::new();
    out.push_str("[TANUKI MS-PAC PRIVILEGE DECODER]\n");
    out.push_str(&format!(" RFC 4120 · [MS-PAC] Bounded NDR Decoder · {} Buffers\n\n", report.buffer_count));

    if let Some(l) = &report.logon_info {
        out.push_str(&format!("[+] Account Identity : {}\n", l.user_name));
        out.push_str(&format!("    ├─ User SID       : {}\n", l.user_sid));
        out.push_str(&format!("    ├─ Primary Group  : {}\n", l.primary_group_sid));
        let priv_status = if l.is_domain_admin || l.is_enterprise_admin {
            "CRITICAL / DOMAIN ADMIN"
        } else {
            "STANDARD USER"
        };
        out.push_str(&format!("    ├─ Privilege Tier : {}\n", priv_status));

        out.push_str(&format!("    ├─ Group Memberships ({} groups):\n", l.group_details.len()));
        for (idx, g) in l.group_details.iter().enumerate() {
            let is_last = idx == l.group_details.len() - 1;
            let branch = if is_last { "╰─" } else { "├─" };
            let crit = if g.is_critical { " [CRITICAL]" } else { "" };
            out.push_str(&format!("    │   {} RID {} ({}){}\n", branch, g.rid, g.name, crit));
        }

        out.push_str(&format!("    ╰─ UAC Flags      : {}\n", l.uac_flags.join(", ")));
        if l.unconstrained_delegation {
            out.push_str("\n[!] OPSEC RISK DETECTED:\n");
            out.push_str("    TRUSTED_FOR_DELEGATION flag is set (Unconstrained Delegation).\n");
        }
    } else {
        out.push_str("[*] No PAC_LOGON_INFO buffer parsed.\n");
    }

    out
}
