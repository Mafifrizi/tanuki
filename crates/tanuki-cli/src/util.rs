use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

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
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        let bytes = word.to_be_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }
    out
}

pub fn fill_dynamic_entropy(buf: &mut [u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let lmeta = fs::symlink_metadata("/dev/urandom")
            .map_err(|e| format!("Failed to stat /dev/urandom: {}", e))?;
        if lmeta.file_type().is_symlink() || !lmeta.file_type().is_char_device() {
            return Err("Refusing untrusted /dev/urandom: expected character device".to_string());
        }
        let mut opts = OpenOptions::new();
        opts.read(true);
        apply_nofollow(&mut opts);
        let mut f = opts
            .open("/dev/urandom")
            .map_err(|e| format!("Failed to open /dev/urandom: {}", e))?;
        let fmeta = f
            .metadata()
            .map_err(|e| format!("Failed to fstat /dev/urandom: {}", e))?;
        if !fmeta.file_type().is_char_device()
            || fmeta.dev() != lmeta.dev()
            || fmeta.ino() != lmeta.ino()
        {
            return Err("Refusing /dev/urandom after device identity mismatch".to_string());
        }
        if let Err(e) = f.read_exact(buf) {
            buf.fill(0);
            return Err(format!(
                "Failed to read cryptographic entropy from /dev/urandom: {}",
                e
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = buf;
        Err("Cryptographic entropy source /dev/urandom is unavailable on non-Unix targets".to_string())
    }
}

#[cfg(target_os = "linux")]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW: i32 = 0x0100;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const O_NOFOLLOW: i32 = 0;

pub fn apply_nofollow(opts: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if O_NOFOLLOW != 0 {
            opts.custom_flags(O_NOFOLLOW);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = opts;
    }
}

pub fn open_regular_nofollow(path: &Path) -> io::Result<(fs::File, fs::Metadata)> {
    let lmeta = fs::symlink_metadata(path)?;
    if lmeta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Refusing to read symbolic link: {}", path.display()),
        ));
    }
    if !lmeta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Refusing to read non-regular file: {}", path.display()),
        ));
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    apply_nofollow(&mut opts);
    let file = opts.open(path)?;
    let fmeta = file.metadata()?;
    if !fmeta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Refusing to read non-regular file: {}", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if fmeta.dev() != lmeta.dev() || fmeta.ino() != lmeta.ino() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("File identity changed during open: {}", path.display()),
            ));
        }
    }
    Ok((file, fmeta))
}

pub fn read_regular_nofollow_bounded(
    path: &Path,
    max_bytes: usize,
) -> io::Result<(Vec<u8>, fs::Metadata)> {
    let (file, fmeta) = open_regular_nofollow(path)?;
    let mut buf = Vec::new();
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut buf)?;
    if buf.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "File '{}' exceeds maximum allowed size ({} bytes)",
                path.display(),
                max_bytes
            ),
        ));
    }
    Ok((buf, fmeta))
}

pub fn read_bytes_nofollow(path: &Path) -> io::Result<Vec<u8>> {
    let (mut file, _) = open_regular_nofollow(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn write_bytes_nofollow(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Refusing to write to symbolic link: {}", path.display()),
            ));
        }
    }
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    apply_nofollow(&mut opts);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    let mut file = opts.open(path)?;
    file.write_all(data)?;
    Ok(())
}

pub fn resolve_current_uid() -> u32 {
    #[cfg(unix)]
    {
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
        if let Ok(uid_str) = std::env::var("UID") {
            if let Ok(uid) = uid_str.trim().parse::<u32>() {
                return uid;
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

    #[cfg(unix)]
    #[test]
    fn test_fill_dynamic_entropy() {
        let mut b1 = [0u8; 16];
        let mut b2 = [0u8; 16];
        assert!(fill_dynamic_entropy(&mut b1).is_ok());
        assert!(fill_dynamic_entropy(&mut b2).is_ok());
        assert_ne!(b1, [0u8; 16]);
    }

    #[cfg(not(unix))]
    #[test]
    fn test_fill_dynamic_entropy_fails_closed_on_non_unix() {
        let mut b = [0u8; 16];
        assert!(fill_dynamic_entropy(&mut b).is_err());
    }

    #[test]
    fn test_resolve_current_uid() {
        let uid = resolve_current_uid();
        #[cfg(not(unix))]
        assert_eq!(uid, 1000);
        #[cfg(unix)]
        assert_eq!(uid, resolve_current_uid());
    }
}
