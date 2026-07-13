use super::*;

impl App {
    /// Import hosts from ssh config into the launcher store (`source=ssh_config`).
    pub fn import_ssh_config(&mut self) -> Result<ImportReport> {
        let report =
            import_ssh_config(self.resolver.as_ref(), &self.store, self.metadata.as_ref())?;
        self.reload_hosts()?;
        Ok(report)
    }

    /// Open the general import prompt (asks for the export directory or file).
    pub fn open_import_prompt(&mut self) {
        let path = crate::import::termius_csv::default_export_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let cursor = path.chars().count();
        self.import_prompt = Some(ImportPromptEdit {
            path,
            cursor,
            error: None,
            preview: None,
        });
        self.mode = AppMode::ImportPrompt;
    }

    pub(crate) fn import_prompt_insert(&mut self, ch: char) {
        if let Some(prompt) = self.import_prompt.as_mut() {
            prompt.cursor = text_input::insert_at(&mut prompt.path, prompt.cursor, ch);
            prompt.error = None;
        }
    }

    pub(crate) fn import_prompt_backspace(&mut self) {
        if let Some(prompt) = self.import_prompt.as_mut() {
            prompt.cursor = text_input::backspace_at(&mut prompt.path, prompt.cursor);
            prompt.error = None;
        }
    }

    pub(crate) fn handle_key_import_prompt(&mut self, key: KeyEvent) -> Result<()> {
        let has_preview = self.import_prompt.as_ref().map(|p| p.preview.is_some()).unwrap_or(false);

        if has_preview {
            match key.code {
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    if let Some(prompt) = self.import_prompt.as_mut() {
                        prompt.preview = None;
                        prompt.error = None;
                    }
                }
                KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.run_import_commit()?;
                }
                _ => {}
            }
            return Ok(());
        }

        match key.code {
            KeyCode::Esc => {
                self.import_prompt = None;
                self.mode = AppMode::Normal;
            }
            KeyCode::Enter | KeyCode::F(2) => self.run_import_preview()?,
            KeyCode::Backspace if key.modifiers.is_empty() => self.import_prompt_backspace(),
            KeyCode::Left | KeyCode::Right | KeyCode::Home | KeyCode::End | KeyCode::Delete => {
                if let Some(p) = self.import_prompt.as_mut() {
                    let mut cursor = p.cursor;
                    text_input::handle_cursor_key(key.code, &mut p.path, &mut cursor);
                    p.cursor = cursor;
                    if key.code == KeyCode::Delete {
                        p.error = None;
                    }
                }
            }
            KeyCode::Char(c)
                if (key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT)
                    && !c.is_control() =>
            {
                self.import_prompt_insert(c);
            }
            _ => {}
        }
        Ok(())
    }

    /// Run the format detection and parse import preview.
    pub(crate) fn run_import_preview(&mut self) -> Result<()> {
        let Some(prompt) = self.import_prompt.as_ref() else {
            return Ok(());
        };
        let raw = prompt.path.trim();
        if raw.is_empty() {
            if let Some(p) = self.import_prompt.as_mut() {
                p.error = Some("Enter a path to import".into());
            }
            return Ok(());
        }

        let mut path = shellexpand_home(raw);
        if path.is_file() {
            // If user pointed directly at L00t.csv, use parent directory for Termius layout.
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_lowercase();
            if name == "l00t.csv" {
                if let Some(parent) = path.parent() {
                    path = parent.to_path_buf();
                }
            }
        }

        match crate::import::detect_import_format(&path) {
            Ok(detected) => {
                match crate::import::parse_preview(&detected) {
                    Ok(preview) => {
                        if let Some(p) = self.import_prompt.as_mut() {
                            p.preview = Some(preview);
                            p.error = None;
                        }
                    }
                    Err(e) => {
                        if let Some(p) = self.import_prompt.as_mut() {
                            p.error = Some(format!("Parse failed: {e:#}"));
                        }
                    }
                }
            }
            Err(e) => {
                if let Some(p) = self.import_prompt.as_mut() {
                    p.error = Some(format!("{e:#}"));
                }
            }
        }
        Ok(())
    }

    /// Commit the parsed preview to the launcher store and OS keyring.
    pub(crate) fn run_import_commit(&mut self) -> Result<()> {
        let Some(prompt) = self.import_prompt.as_ref() else {
            return Ok(());
        };
        let Some(preview) = prompt.preview.as_ref() else {
            return Ok(());
        };

        match crate::import::commit_import(
            &self.store,
            self.password_store.as_ref(),
            preview,
        ) {
            Ok(report) => {
                let mut msg = format!(
                    "{}: {} hosts new, {} skipped · {} passwords + {} passphrases stored",
                    preview.source_type,
                    report.hosts_imported,
                    report.skipped,
                    report.passwords_stored,
                    report.passphrases_stored,
                );
                if report.identities_created > 0 {
                    msg.push_str(&format!(" · {} new keys", report.identities_created));
                }
                if report.keyring_failures > 0 {
                    msg.push_str(&format!(
                        " · ⚠ {} keyring writes failed verification",
                        report.keyring_failures
                    ));
                }
                self.host_notice = Some(msg);
                self.import_prompt = None;
                self.mode = AppMode::Normal;
                self.reload_hosts()?;
            }
            Err(e) => {
                if let Some(p) = self.import_prompt.as_mut() {
                    p.error = Some(format!("Commit failed: {e:#}"));
                }
            }
        }
        Ok(())
    }

    /// Export launcher-native hosts to `config_dir/exported.conf`.
    pub fn export_ssh_config(&mut self) -> Result<std::path::PathBuf> {
        export_launcher_hosts(&self.store)
    }
}
