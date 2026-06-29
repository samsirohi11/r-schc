use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::error::{Result, SchcError};

/// One entry in a SID registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SidItem {
    /// Numeric SID value.
    pub sid: u64,
    /// Stable identifier associated with the SID.
    pub identifier: String,
    /// Optional SID namespace.
    pub namespace: Option<String>,
    /// Module name that defined this SID.
    #[serde(rename = "module-name")]
    pub module_name: Option<String>,
    /// Optional item type from the SID file `type` field.
    #[serde(rename = "type")]
    pub item_type: Option<String>,
    /// Optional lifecycle status.
    pub status: Option<String>,
}

/// Deterministic SID registry for identifier and SID lookups.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SidRegistry {
    by_identifier: BTreeMap<String, SidItem>,
    by_sid: BTreeMap<u64, String>,
}

#[derive(Debug, Deserialize)]
struct SidFileEnvelope {
    #[serde(rename = "ietf-sid-file:sid-file")]
    sid_file: SidFile,
}

#[derive(Debug, Deserialize)]
struct SidFile {
    #[serde(rename = "module-name")]
    module_name: Option<String>,
    item: Vec<SidItem>,
}

impl SidRegistry {
    /// Loads a SID registry from a JSON file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Json`] when the file cannot be read or parsed.
    pub fn load_path(path: impl AsRef<Path>) -> Result<Self> {
        let data = fs::read_to_string(path).map_err(|error| SchcError::Json(error.to_string()))?;
        Self::from_json_str(&data)
    }

    /// Loads a SID registry from a standard SID JSON document.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Json`] when `data` is not valid SID JSON.
    pub fn from_json_str(data: &str) -> Result<Self> {
        let envelope: SidFileEnvelope =
            serde_json::from_str(data).map_err(|error| SchcError::Json(error.to_string()))?;
        let mut registry = Self::default();

        for mut item in envelope.sid_file.item {
            if item.module_name.is_none() {
                item.module_name.clone_from(&envelope.sid_file.module_name);
            }
            registry.insert(item);
        }

        Ok(registry)
    }

    /// Inserts or replaces a SID item.
    pub fn insert(&mut self, item: SidItem) {
        if let Some(previous) = self.by_identifier.get(&item.identifier) {
            self.by_sid.remove(&previous.sid);
        }

        if let Some(previous_identifier) = self.by_sid.get(&item.sid) {
            self.by_identifier.remove(previous_identifier);
        }

        self.by_sid.insert(item.sid, item.identifier.clone());
        self.by_identifier.insert(item.identifier.clone(), item);
    }

    /// Resolves an identifier to its numeric SID.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::MissingSidIdentifier`] when `identifier` is not in the
    /// registry.
    pub fn sid(&self, identifier: &str) -> Result<u64> {
        self.by_identifier
            .get(identifier)
            .map(|item| item.sid)
            .ok_or_else(|| SchcError::MissingSidIdentifier {
                identifier: identifier.to_owned(),
            })
    }

    /// Resolves a numeric SID to its identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::UnknownSid`] when `sid` is not in the registry.
    pub fn identifier(&self, sid: u64) -> Result<&str> {
        self.by_sid
            .get(&sid)
            .map(String::as_str)
            .ok_or(SchcError::UnknownSid { sid })
    }
}
