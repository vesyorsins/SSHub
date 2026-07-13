use std::path::Path;
use anyhow::{Result, Context};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MremoteConnection {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
}

/// A simple, dependency-free attribute extractor for XML tags.
pub fn get_xml_attr(tag: &str, attr: &str) -> Option<String> {
    let patterns = [
        format!("{}=\"", attr),
        format!("{}='", attr),
    ];
    for pat in &patterns {
        if let Some(idx) = tag.find(pat) {
            let start = idx + pat.len();
            let rest = &tag[start..];
            let quote = if pat.ends_with('"') { '"' } else { '\'' };
            if let Some(end) = rest.find(quote) {
                // Decode XML entities (e.g. &amp;, &quot;, &lt;, &gt;)
                let val = &rest[..end];
                return Some(decode_xml_entities(val));
            }
        }
    }
    None
}

fn decode_xml_entities(val: &str) -> String {
    val.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

/// Parse mRemoteNG confCons.xml content.
pub fn parse_mremoteng_xml(content: &str) -> Vec<MremoteConnection> {
    let mut connections = Vec::new();
    
    // We scan for "<Node " tags
    let mut rest = content;
    while let Some(start_idx) = rest.find("<Node ") {
        rest = &rest[start_idx..];
        if let Some(end_idx) = rest.find('>') {
            let tag = &rest[..=end_idx];
            rest = &rest[end_idx + 1..];

            // Parse if it's a Connection
            let node_type = get_xml_attr(tag, "Type");
            if node_type.as_deref() == Some("Connection") {
                let name = get_xml_attr(tag, "Name").unwrap_or_default();
                let host = get_xml_attr(tag, "Hostname")
                    .or_else(|| get_xml_attr(tag, "Host"))
                    .unwrap_or_default();
                
                let protocol = get_xml_attr(tag, "Protocol").unwrap_or_default().to_uppercase();
                // Filter to SSH/SFTP only (or empty protocol), skip RDP/VNC/HTTP
                let is_ssh = protocol.is_empty() 
                    || protocol.contains("SSH") 
                    || protocol.contains("SFTP");
                
                if !host.is_empty() && !name.is_empty() && is_ssh {
                    let port = get_xml_attr(tag, "Port")
                        .and_then(|p| p.parse::<u16>().ok())
                        .unwrap_or(22);
                    
                    let username = get_xml_attr(tag, "Username")
                        .map(|u| u.trim().to_string())
                        .filter(|u| !u.is_empty());

                    connections.push(MremoteConnection {
                        name,
                        host,
                        port,
                        username,
                    });
                }
            }
        } else {
            break;
        }
    }

    connections
}

/// Parse mRemoteNG confCons.xml file.
pub fn parse_mremoteng_file(path: &Path) -> Result<Vec<MremoteConnection>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading mRemoteNG file '{}'", path.display()))?;
    Ok(parse_mremoteng_xml(&content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mremoteng_xml() {
        let content = r#"
<?xml version="1.0" encoding="utf-8"?>
<Connections>
    <Node Name="Server1" Type="Connection" Hostname="10.0.0.5" Port="22" Username="root" Protocol="SSH2" />
    <Node Name="Server2" Type="Connection" Host="192.168.1.10" Port="2222" Username="admin" Protocol="SFTP" />
    <Node Name="Web" Type="Connection" Hostname="google.com" Port="80" Username="web" Protocol="HTTP" />
</Connections>
"#;
        let conns = parse_mremoteng_xml(content);
        assert_eq!(conns.len(), 2);

        assert_eq!(conns[0].name, "Server1");
        assert_eq!(conns[0].host, "10.0.0.5");
        assert_eq!(conns[0].port, 22);
        assert_eq!(conns[0].username, Some("root".to_string()));

        assert_eq!(conns[1].name, "Server2");
        assert_eq!(conns[1].host, "192.168.1.10");
        assert_eq!(conns[1].port, 2222);
        assert_eq!(conns[1].username, Some("admin".to_string()));
    }
}
