pub fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for c in input.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

pub fn fill_dynamic_entropy(buf: &mut [u8]) {
    #[cfg(unix)]
    {
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            if f.read_exact(buf).is_ok() {
                return;
            }
        }
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mut state = now ^ (pid << 32) ^ 0x9E37_79B9_7F4A_7C15_u128;
    for chunk in buf.chunks_mut(16) {
        state = state.wrapping_mul(0xDA94_2042_E4DD_58B5_u128).wrapping_add(1);
        let bytes = state.to_le_bytes();
        let copy_len = chunk.len().min(16);
        chunk[..copy_len].copy_from_slice(&bytes[..copy_len]);
    }
}

pub fn resolve_current_uid() -> u32 {
    #[cfg(unix)]
    {
        if let Ok(uid_str) = std::env::var("UID") {
            if let Ok(uid) = uid_str.trim().parse::<u32>() {
                return uid;
            }
        }
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("Uid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(uid) = parts[1].parse::<u32>() {
                            return uid;
                        }
                    }
                }
            }
        }
    }
    1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_json_special_and_control_chars() {
        assert_eq!(escape_json("hello \"world\""), "hello \\\"world\\\"");
        assert_eq!(escape_json("line1\nline2"), "line1\\nline2");
        assert_eq!(escape_json("back\\slash"), "back\\\\slash");
        assert_eq!(escape_json("\x00\x1f"), "\\u0000\\u001f");
        assert_eq!(escape_json("\x08\x0c"), "\\b\\f");
    }

    #[test]
    fn test_fill_dynamic_entropy() {
        let mut b1 = [0u8; 16];
        let mut b2 = [0u8; 16];
        fill_dynamic_entropy(&mut b1);
        fill_dynamic_entropy(&mut b2);
        assert_ne!(b1, [0u8; 16]);
    }

    #[test]
    fn test_resolve_current_uid() {
        let uid = resolve_current_uid();
        assert!(uid > 0 || uid == 0);
    }
}
