use anyhow::{Context, Result};
use std::fs;
use std::hash::Hash;
use std::path::PathBuf;

use crate::common::Address;
use serde::Deserialize;

pub use indexmap::IndexMap;

#[derive(Debug, Default, Deserialize)]
pub struct FuzzwareConfig {
    pub memory_map: Option<IndexMap<String, MemoryMap>>,
}

#[derive(Debug, Deserialize)]
pub struct MemoryMap {
    #[serde(rename = "base_addr")]
    pub address: Address,
    pub size: Address,
    pub permissions: String,
}

impl FuzzwareConfig {
    pub fn merge(&mut self, config: FuzzwareConfig) {
        merge(&mut self.memory_map, config.memory_map);
    }
}

pub fn merge<K: Eq + Hash, V>(this: &mut Option<IndexMap<K, V>>, that: Option<IndexMap<K, V>>) {
    if let Some(that) = that {
        match this {
            Some(this) => {
                for (key, value) in that.into_iter() {
                    let old = this.insert(key, value);

                    if old.is_some() {
                        println!("include replaced old value");
                    }
                }
            }
            None => *this = Some(that),
        }
    }
}

impl FuzzwareConfig {
    pub fn load(config_path: &PathBuf) -> Result<FuzzwareConfig> {
        // merge config file
        let mut fuzzware_config = FuzzwareConfig::default();

        let config_raw = fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read Fuzzware config file: {:?}", config_path))?;

        // load main config
        fuzzware_config.merge(serde_yaml::from_str(&config_raw).with_context(|| {
            format!(
                "Failed to deserialize Fuzzware config file: {:?}",
                config_path
            )
        })?);

        Ok(fuzzware_config)
    }
}
