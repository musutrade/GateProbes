use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
const COMPAT_SCHEMA_VERSION: u32 = 1;
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CanaryState {
    pub schema_version: u32,
    pub enabled: bool,
    pub slice: String,
    pub updated_at: String,
    #[serde(default)]
    pub history: Vec<CanaryEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CanaryEvent {
    pub action: String,
    pub slice: String,
    pub at: String,
}

pub(crate) fn set_canary(path: &Path, slice: &str) -> Result<CanaryState> {
    let mut state = read_canary(path)?.unwrap_or(CanaryState {
        schema_version: COMPAT_SCHEMA_VERSION,
        enabled: false,
        slice: String::new(),
        updated_at: String::new(),
        history: Vec::new(),
    });
    state.enabled = true;
    state.slice = slice.into();
    state.updated_at = chrono::Utc::now().to_rfc3339();
    state.history.push(CanaryEvent {
        action: "enable".into(),
        slice: slice.into(),
        at: state.updated_at.clone(),
    });
    write_canary(path, &state)?;
    Ok(state)
}

pub(crate) fn rollback(path: &Path) -> Result<CanaryState> {
    let mut state =
        read_canary(path)?.ok_or_else(|| anyhow::anyhow!("canary state does not exist"))?;
    state.enabled = false;
    state.updated_at = chrono::Utc::now().to_rfc3339();
    state.history.push(CanaryEvent {
        action: "rollback".into(),
        slice: state.slice.clone(),
        at: state.updated_at.clone(),
    });
    write_canary(path, &state)?;
    Ok(state)
}

fn read_canary(path: &Path) -> Result<Option<CanaryState>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("parse canary state")?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read canary state {}", path.display())),
    }
}

fn write_canary(path: &Path, state: &CanaryState) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if let Ok(meta) = fs::symlink_metadata(path) {
        anyhow::ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "state must be a regular file"
        );
    }
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(output.as_file_mut(), state)?;
    output.as_file_mut().sync_all()?;
    output
        .persist(path)
        .map_err(|e| e.error)
        .context("publish operator state")?;
    Ok(())
}
