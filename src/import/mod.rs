pub mod termius_csv;
pub mod putty;
pub mod mremoteng;

use std::path::{Path, PathBuf};
use anyhow::{Result, Context};
use crate::store::{LauncherStore, NewHost, HostSource, NewIdentity};
use crate::credentials::PasswordStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedImport {
    Termius(PathBuf),
    PuttyReg(PathBuf),
    PuttyUnix(PathBuf),
    Mremote(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedHost {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ssh_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedIdentity {
    pub name: String,
    pub pem_path: PathBuf,
    pub passphrase: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPreview {
    pub source_type: String,
    pub hosts: Vec<ImportedHost>,
    pub identities: Vec<ImportedIdentity>,
}

pub fn detect_import_format(path: &Path) -> Result<DetectedImport> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("metadata for '{}'", path.display()))?;
    
    if metadata.is_dir() {
        let loot = path.join("L00t.csv");
        if loot.is_file() {
            return Ok(DetectedImport::Termius(path.to_path_buf()));
        }
        
        // Check for PuTTY Unix sessions directory
        if let Ok(entries) = std::fs::read_dir(path) {
            let mut has_files = false;
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    has_files = true;
                    break;
                }
            }
            if has_files {
                return Ok(DetectedImport::PuttyUnix(path.to_path_buf()));
            }
        }
        anyhow::bail!("Directory '{}' does not look like a Termius export (missing L00t.csv) or PuTTY sessions folder.", path.display())
    } else {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
        if ext == "reg" {
            return Ok(DetectedImport::PuttyReg(path.to_path_buf()));
        } else if ext == "xml" || name == "confcons.xml" {
            return Ok(DetectedImport::Mremote(path.to_path_buf()));
        } else if name == "l00t.csv" {
            if let Some(parent) = path.parent() {
                return Ok(DetectedImport::Termius(parent.to_path_buf()));
            }
        }
        anyhow::bail!("Unrecognized import file format for '{}'. Must be a .reg file (PuTTY), confCons.xml (mRemoteNG), L00t.csv (Termius), or a folder.", path.display())
    }
}

pub fn parse_preview(detected: &DetectedImport) -> Result<ImportPreview> {
    match detected {
        DetectedImport::Termius(dir) => {
            let loot_path = dir.join("L00t.csv");
            let content = std::fs::read_to_string(&loot_path)
                .with_context(|| format!("reading L00t.csv at '{}'", loot_path.display()))?;
            let csv_rows = termius_csv::parse_loot_csv(&content);
            let key_files = termius_csv::discover_keys(&dir.join("ssh_keys"));

            let mut identities = Vec::new();
            for kf in &key_files {
                let name = if kf.base.is_empty() {
                    format!("termius-{}", kf.fingerprint)
                } else {
                    kf.base.clone()
                };
                identities.push(ImportedIdentity {
                    name,
                    pem_path: kf.pem_path.clone(),
                    passphrase: kf.passphrase.clone(),
                });
            }

            let mut hosts = Vec::new();
            for row in &csv_rows {
                let name = if row.label.is_empty() {
                    row.host.clone()
                } else {
                    row.label.clone()
                };
                if name.is_empty() {
                    continue;
                }
                
                // Find matching key path if any
                let mut ssh_key_path = None;
                let hint = row.ssh_key.trim();
                if !hint.is_empty() && !hint.starts_with("key_id:") {
                    if let Some(kf) = key_files.iter().find(|k| k.base == hint || kf_name(k) == hint) {
                        ssh_key_path = Some(kf.pem_path.clone());
                    }
                }

                let username = (!row.username.is_empty()).then(|| row.username.clone());
                let password = (!row.password.is_empty()).then(|| row.password.clone());

                hosts.push(ImportedHost {
                    name,
                    address: row.host.clone(),
                    port: row.port,
                    username,
                    password,
                    ssh_key_path,
                });
            }

            Ok(ImportPreview {
                source_type: "Termius".into(),
                hosts,
                identities,
            })
        }
        DetectedImport::PuttyReg(file) => {
            let bytes = std::fs::read(file)
                .with_context(|| format!("reading reg file '{}'", file.display()))?;
            let content = putty::decode_reg_bytes(&bytes);
            let putty_sessions = putty::parse_putty_reg(&content);

            let mut hosts = Vec::new();
            for s in &putty_sessions {
                hosts.push(ImportedHost {
                    name: s.name.clone(),
                    address: s.host.clone(),
                    port: s.port,
                    username: s.username.clone(),
                    password: None,
                    ssh_key_path: s.public_key_file.clone(),
                });
            }

            Ok(ImportPreview {
                source_type: "PuTTY (.reg)".into(),
                hosts,
                identities: Vec::new(),
            })
        }
        DetectedImport::PuttyUnix(dir) => {
            let putty_sessions = putty::parse_putty_unix_dir(dir)?;
            let mut hosts = Vec::new();
            for s in &putty_sessions {
                hosts.push(ImportedHost {
                    name: s.name.clone(),
                    address: s.host.clone(),
                    port: s.port,
                    username: s.username.clone(),
                    password: None,
                    ssh_key_path: s.public_key_file.clone(),
                });
            }

            Ok(ImportPreview {
                source_type: "PuTTY (Unix)".into(),
                hosts,
                identities: Vec::new(),
            })
        }
        DetectedImport::Mremote(file) => {
            let mremote_conns = mremoteng::parse_mremoteng_file(file)?;
            let mut hosts = Vec::new();
            for s in &mremote_conns {
                hosts.push(ImportedHost {
                    name: s.name.clone(),
                    address: s.host.clone(),
                    port: s.port,
                    username: s.username.clone(),
                    password: None,
                    ssh_key_path: None,
                });
            }

            Ok(ImportPreview {
                source_type: "mRemoteNG".into(),
                hosts,
                identities: Vec::new(),
            })
        }
    }
}

fn kf_name(kf: &termius_csv::CsvKeyFile) -> String {
    if kf.base.is_empty() {
        format!("termius-{}", kf.fingerprint)
    } else {
        kf.base.clone()
    }
}

fn store_credential_verified(store: &dyn PasswordStore, key: &str, value: &str) -> Result<()> {
    store
        .set(key, value)
        .with_context(|| format!("set {key}"))?;
    match store.get(key) {
        Ok(Some(roundtrip)) if roundtrip == value => Ok(()),
        Ok(Some(_)) => anyhow::bail!(
            "keyring roundtrip for {key} returned a different value — \
             check that only one keyring backend is active"
        ),
        Ok(None) => anyhow::bail!(
            "keyring write for {key} silently dropped — no D-Bus session / \
             locked wallet / no secret service?"
        ),
        Err(e) => Err(e).with_context(|| format!("verify {key}")),
    }
}

pub fn commit_import(
    store: &LauncherStore,
    password_store: &dyn PasswordStore,
    preview: &ImportPreview,
) -> Result<termius_csv::CsvImportReport> {
    let mut report = termius_csv::CsvImportReport::default();
    
    // 1. Write identities
    let mut identity_id_by_path = std::collections::HashMap::new();
    for identity in &preview.identities {
        let name = identity.name.clone();
        let identity_id = if let Some(existing) = store.get_identity_by_name(&name)? {
            let dest = termius_csv::copy_key_into_ssh(&identity.pem_path, &name)?;
            if existing.private_key.as_deref() != Some(dest.as_path()) {
                store.update_identity(
                    existing.id,
                    &crate::store::IdentityUpdate {
                        private_key: Some(Some(dest)),
                        has_password: Some(identity.passphrase.is_some()),
                        ..Default::default()
                    },
                )?;
            }
            existing.id
        } else {
            let dest = termius_csv::copy_key_into_ssh(&identity.pem_path, &name)?;
            let new_ident = store.create_identity(&NewIdentity {
                name: name.clone(),
                username: None,
                private_key: Some(dest),
                certificate: None,
                sort_order: 0,
                has_password: identity.passphrase.is_some(),
            })?;
            report.identities_created += 1;
            new_ident.id
        };

        if let Some(passphrase) = &identity.passphrase {
            if store_credential_verified(password_store, &crate::credentials::identity_key(identity_id), passphrase).is_ok() {
                report.passphrases_stored += 1;
            } else {
                report.keyring_failures += 1;
            }
        }
        identity_id_by_path.insert(identity.pem_path.clone(), identity_id);
    }

    // Also check for any custom PuTTY keys that aren't managed in preview.identities.
    // If a host references a key that exists, we can create an identity for it.
    let mut custom_key_identities = std::collections::HashMap::new();
    for host in &preview.hosts {
        if let Some(ref key_path) = host.ssh_key_path {
            if !identity_id_by_path.contains_key(key_path) && key_path.exists() {
                let name = key_path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("putty-key")
                    .to_string();
                let identity_id = if let Some(existing) = store.get_identity_by_name(&name)? {
                    existing.id
                } else {
                    let new_ident = store.create_identity(&NewIdentity {
                        name: name.clone(),
                        username: None,
                        private_key: Some(key_path.clone()),
                        certificate: None,
                        sort_order: 0,
                        has_password: false,
                    })?;
                    report.identities_created += 1;
                    new_ident.id
                };
                custom_key_identities.insert(key_path.clone(), identity_id);
            }
        }
    }

    // 2. Write hosts
    for host in &preview.hosts {
        if host.name.is_empty() {
            report.skipped += 1;
            continue;
        }

        let has_password = host.password.is_some();
        let host_id = match store.get_host_by_name(&host.name)? {
            Some(existing) => {
                report.skipped += 1;
                existing.id
            }
            None => {
                let identity_id = host.ssh_key_path.as_ref()
                    .and_then(|p| identity_id_by_path.get(p).copied().or_else(|| custom_key_identities.get(p).copied()));
                
                let new_host = store.create_host(&NewHost {
                    name: host.name.clone(),
                    address: host.address.clone(),
                    port: host.port,
                    username: host.username.clone(),
                    identity_id,
                    source: HostSource::Launcher,
                    has_password,
                    ..Default::default()
                })?;
                report.hosts_imported += 1;
                new_host.id
            }
        };

        if let Some(ref password) = host.password {
            if store_credential_verified(password_store, &crate::credentials::host_key(host_id), password).is_ok() {
                report.passwords_stored += 1;
            } else {
                report.keyring_failures += 1;
            }
        }
    }

    Ok(report)
}
