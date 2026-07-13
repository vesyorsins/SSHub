use std::path::{Path, PathBuf};
use anyhow::{Result, Context};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PuttySession {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub public_key_file: Option<PathBuf>,
}

/// URL-decodes a PuTTY session name (e.g. converting "%20" to spaces).
pub fn url_decode(s: &str) -> String {
    let mut res = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(a), Some(b)) = (h1, h2) {
                if let Ok(val) = u8::from_str_radix(&format!("{a}{b}"), 16) {
                    res.push(val as char);
                    continue;
                }
            }
            res.push('%');
            if let Some(x) = h1 { res.push(x); }
            if let Some(x) = h2 { res.push(x); }
        } else {
            res.push(c);
        }
    }
    res
}

/// Decodes raw registry file bytes, handling UTF-16 (LE or BE) or falling back to UTF-8.
pub fn decode_reg_bytes(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) {
        let utf16: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&utf16).unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        let utf16: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&utf16).unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// Parse a PuTTY registry export `.reg` file.
pub fn parse_putty_reg(content: &str) -> Vec<PuttySession> {
    let mut sessions = Vec::new();
    let mut current_session: Option<(String, HashMap<String, String>)> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            // Save the previous session if any
            if let Some((name, attrs)) = current_session.take() {
                if let Some(session) = build_session(name, attrs) {
                    sessions.push(session);
                }
            }

            // Check if this is a PuTTY session key
            let key_pattern = "\\Software\\SimonTatham\\PuTTY\\Sessions\\";
            if let Some(idx) = line.find(key_pattern) {
                let start = idx + key_pattern.len();
                let end = line.rfind(']').unwrap_or(line.len());
                let raw_name = &line[start..end];
                let session_name = url_decode(raw_name);
                current_session = Some((session_name, HashMap::new()));
            }
        } else if let Some((_, attrs)) = current_session.as_mut() {
            if let Some(eq_idx) = line.find('=') {
                let key = line[..eq_idx].trim().trim_matches('"').to_string();
                let val_raw = line[eq_idx + 1..].trim();
                let val = if val_raw.starts_with('"') && val_raw.ends_with('"') {
                    let inner = &val_raw[1..val_raw.len() - 1];
                    inner.replace("\\\\", "\\").replace("\\\"", "\"")
                } else if val_raw.starts_with("dword:") {
                    let hex_val = &val_raw[6..];
                    if let Ok(num) = u32::from_str_radix(hex_val, 16) {
                        num.to_string()
                    } else {
                        String::new()
                    }
                } else {
                    val_raw.to_string()
                };
                if !val.is_empty() {
                    attrs.insert(key, val);
                }
            }
        }
    }

    if let Some((name, attrs)) = current_session {
        if let Some(session) = build_session(name, attrs) {
            sessions.push(session);
        }
    }

    sessions
}

/// Parse PuTTY Unix session flat text files from a directory.
pub fn parse_putty_unix_dir(dir: &Path) -> Result<Vec<PuttySession>> {
    let mut sessions = Vec::new();
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading PuTTY Unix sessions directory '{}'", dir.display()))?;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if filename.is_empty() {
            continue;
        }

        let session_name = url_decode(filename);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading PuTTY session file '{}'", path.display()))?;

        let mut attrs = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if let Some(eq_idx) = line.find('=') {
                let key = line[..eq_idx].trim().to_string();
                let val = line[eq_idx + 1..].trim().to_string();
                attrs.insert(key, val);
            }
        }

        if let Some(session) = build_session(session_name, attrs) {
            sessions.push(session);
        }
    }

    Ok(sessions)
}

fn build_session(name: String, attrs: HashMap<String, String>) -> Option<PuttySession> {
    // PuTTY Default Settings shouldn't be imported as a host
    if name == "Default%20Settings" || name == "Default Settings" {
        return None;
    }

    let host = attrs.get("HostName")?.trim().to_string();
    if host.is_empty() {
        return None;
    }

    let port = attrs.get("PortNumber")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(22);

    let username = attrs.get("UserName")
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());

    let public_key_file = attrs.get("PublicKeyFile")
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
        .map(PathBuf::from);

    Some(PuttySession {
        name,
        host,
        port,
        username,
        public_key_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("My%20Session"), "My Session");
        assert_eq!(url_decode("a%20b%20c"), "a b c");
        assert_eq!(url_decode("normal"), "normal");
    }

    #[test]
    fn test_parse_putty_reg() {
        let content = r#"
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\My%20Session]
"HostName"="192.168.1.50"
"PortNumber"=dword:00000016
"UserName"="admin"
"PublicKeyFile"="C:\\keys\\key.ppk"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\AnotherOne]
"HostName"="google.com"
"PortNumber"=dword:00000050
"#;
        let sessions = parse_putty_reg(content);
        assert_eq!(sessions.len(), 2);

        assert_eq!(sessions[0].name, "My Session");
        assert_eq!(sessions[0].host, "192.168.1.50");
        assert_eq!(sessions[0].port, 22);
        assert_eq!(sessions[0].username, Some("admin".to_string()));
        assert_eq!(sessions[0].public_key_file, Some(PathBuf::from("C:\\keys\\key.ppk")));

        assert_eq!(sessions[1].name, "AnotherOne");
        assert_eq!(sessions[1].host, "google.com");
        assert_eq!(sessions[1].port, 80);
        assert_eq!(sessions[1].username, None);
        assert_eq!(sessions[1].public_key_file, None);
    }
}
