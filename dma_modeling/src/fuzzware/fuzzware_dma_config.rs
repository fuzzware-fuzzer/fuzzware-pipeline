use crate::dma_config::DmaConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::BufWriter,
    path::PathBuf,
};

use fxhash::FxHashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct FuzzwarePeripheral {
    class: Option<String>,
    #[serde(flatten)]
    descriptors: DmaConfig,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FuzzwareDmaConfig {
    pub peripherals: FxHashMap<String, FuzzwarePeripheral>,
}

const FUZZWARE_CLASS_NAME: &str = "fuzzware_harness.peripherals.generic_dma.GenericDMAC";
impl FuzzwareDmaConfig {
    pub fn load(path: &PathBuf) -> Result<Self> {
        let config_raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read DMA config file: {:?}", path))?;

        // load main config
        let dma_config = serde_yaml::from_str(&config_raw)
            .with_context(|| format!("Failed to deserialize Fuzzware config file: {:?}", path))?;

        Ok(dma_config)
    }

    pub fn save(&self, out_path: &PathBuf) -> Result<()> {
        let writer = BufWriter::new(File::create(out_path).with_context(|| {
            format!(
                "Failed to open file for writing fuzzware DMA config (does it exist?): {:?}",
                out_path
            )
        })?);
        serde_yaml::to_writer(writer, self).with_context(|| {
            format!(
                "Failed to write fuzzware dma config {:?} to: {:?}",
                self, out_path
            )
        })?;

        Ok(())
    }

    pub fn from_dma_config(config: DmaConfig) -> Self {
        Self {
            peripherals: [(
                String::from("my_dma_periph"),
                FuzzwarePeripheral {
                    class: Some(String::from(FUZZWARE_CLASS_NAME)),
                    descriptors: config,
                },
            )]
            .into_iter()
            .collect(),
        }
    }
}
