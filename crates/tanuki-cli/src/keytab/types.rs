use crate::util::escape_json;

pub fn enctype_name(keytype: i16) -> String {
    match keytype {
        1 => "des-cbc-crc".to_string(),
        2 => "des-cbc-md4".to_string(),
        3 => "des-cbc-md5".to_string(),
        16 => "des3-cbc-sha1-kd".to_string(),
        17 => "aes128-cts-hmac-sha1-96".to_string(),
        18 => "aes256-cts-hmac-sha1-96".to_string(),
        19 => "aes128-cts-hmac-sha256-128".to_string(),
        20 => "aes256-cts-hmac-sha384-192".to_string(),
        23 => "rc4-hmac".to_string(),
        24 => "rc4-hmac-exp".to_string(),
        other => format!("unknown({})", other),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeytabEntry {
    pub principal: String,
    pub realm: String,
    pub components: Vec<String>,
    pub vno: u32,
    pub keytype: i16,
    pub enctype_name: String,
    pub key_len: u16,
    pub key_hex: String,
    pub timestamp: u32,
}

impl KeytabEntry {
    pub fn is_modern_aes(&self) -> bool {
        matches!(self.keytype, 17 | 18 | 19 | 20)
    }

    pub fn to_json(&self) -> String {
        let escaped_principal = escape_json(&self.principal);
        let escaped_realm = escape_json(&self.realm);
        let comps_json = if self.components.is_empty() {
            "[]".to_string()
        } else {
            let formatted = self
                .components
                .iter()
                .map(|c| format!("\"{}\"", escape_json(c)))
                .collect::<Vec<_>>()
                .join(",\n      ");
            format!("[\n      {}\n    ]", formatted)
        };

        format!(
            "  {{\n    \"principal\": \"{}\",\n    \"realm\": \"{}\",\n    \"components\": {},\n    \"vno\": {},\n    \"keytype\": {},\n    \"enctype_name\": \"{}\",\n    \"key_len\": {},\n    \"key_hex\": \"{}\",\n    \"timestamp\": {}\n  }}",
            escaped_principal,
            escaped_realm,
            comps_json,
            self.vno,
            self.keytype,
            escape_json(&self.enctype_name),
            self.key_len,
            self.key_hex,
            self.timestamp
        )
    }
}

pub fn entries_to_json(entries: &[KeytabEntry]) -> String {
    if entries.is_empty() {
        return "[]".to_string();
    }
    let body = entries
        .iter()
        .map(|e| e.to_json())
        .collect::<Vec<_>>()
        .join(",\n");
    format!("[\n{}\n]", body)
}
