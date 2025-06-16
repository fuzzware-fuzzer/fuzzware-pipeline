use crate::common::MmioAddress;
use crate::dma_analysis::{
    AccessAnalysisResult, DmaBufMeta, PointerCounterExample, PointerType, RxTxPair,
};
use crate::hoedur::bintrace::Access;
use anyhow::{Context, Result};
use log::info;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::{fs, usize};

use fxhash::FxHashMap;
use serde::{Deserialize, Serialize};

use crate::serialization_helpers::{hex_key, hex_vals};
use bincode;

#[derive(Debug, Deserialize, Serialize)]
pub struct DmaAnalysisSnippet {
    #[serde(serialize_with = "hex_key", default)]
    pub detected_candidates: FxHashMap<MmioAddress, DmaBufMeta>,

    #[serde(serialize_with = "hex_key", default)]
    pub mmio_pointer_counterexamples: FxHashMap<MmioAddress, PointerCounterExample>,
    #[serde(serialize_with = "hex_key", default)]
    pub misaligned_mmio_writes: FxHashMap<MmioAddress, Access>,
    #[serde(default)]
    pub discarded_candidates: Vec<DmaBufMeta>,

    #[serde(serialize_with = "hex_key", default)]
    pub analysis_by_mmio_addr: FxHashMap<MmioAddress, Vec<AccessAnalysisResult>>,

    #[serde(serialize_with = "hex_key", default)]
    pub guessed_type_by_mmio_addr: FxHashMap<MmioAddress, PointerType>,

    #[serde(default)]
    pub collided_descriptors: Vec<DmaBufMeta>,

    #[serde(serialize_with = "hex_vals", default)]
    pub ambiguous_candidate_mmio_addrs: Vec<MmioAddress>,

    #[serde(default)]
    pub rx_tx_pairs: Vec<RxTxPair>,
}

impl Default for DmaAnalysisSnippet {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaAnalysisSnippet {
    pub fn new() -> Self {
        DmaAnalysisSnippet {
            detected_candidates: Default::default(),
            mmio_pointer_counterexamples: Default::default(),
            misaligned_mmio_writes: Default::default(),
            discarded_candidates: Default::default(),
            analysis_by_mmio_addr: Default::default(),
            collided_descriptors: Default::default(),
            ambiguous_candidate_mmio_addrs: Default::default(),
            rx_tx_pairs: Default::default(),
            guessed_type_by_mmio_addr: Default::default(),
        }
    }

    pub fn set_rx_tx_pairs(&mut self, rx_tx_pairs: &FxHashMap<MmioAddress, RxTxPair>) {
        self.rx_tx_pairs = rx_tx_pairs.values().copied().collect();
    }

    pub fn minimize(&mut self, max_entries_per_mmio: usize) {
        let half = max_entries_per_mmio / 2;
        for (mmio_addr, results) in &mut self.analysis_by_mmio_addr {
            let cur_len = results.len();
            if cur_len > max_entries_per_mmio {
                info!("Dropping analysis entries for {mmio_addr:#x} from {cur_len} down to {max_entries_per_mmio}");
                results.drain(half..cur_len - half);
            }
        }
    }
}

pub fn load_snippet_directory(snipdir: &PathBuf) -> Result<Vec<DmaAnalysisSnippet>> {
    let snippet_paths = fs::read_dir(snipdir).unwrap();
    let mut snippets: Vec<DmaAnalysisSnippet> = Vec::default();

    for snip_path in snippet_paths
        .filter_map(|r| r.ok())
        .filter(|p| p.file_type().unwrap().is_file())
        .map(|p| p.path())
    {
        let snippet_raw = fs::read_to_string(&snip_path)
            .with_context(|| format!("Failed to read from snippet file: {:?}", snip_path))?;

        snippets.push(
            serde_yaml::from_str(&snippet_raw).with_context(|| {
                format!("Failed to deserialize DMA snippet file: {:?}", snip_path)
            })?,
        );
    }

    Ok(snippets)
}

pub fn load_snippet_directory_bin(snipdir: &PathBuf) -> Result<Vec<DmaAnalysisSnippet>> {
    let snippet_paths = fs::read_dir(snipdir).unwrap();
    let mut snippets: Vec<DmaAnalysisSnippet> = Vec::default();

    for snip_path in snippet_paths
        .filter_map(|r| r.ok())
        .filter(|p| p.file_type().unwrap().is_file())
        .map(|p| p.path())
    {
        let f = File::open(&snip_path)?;
        let mut reader = BufReader::new(f);

        snippets.push(bincode::deserialize_from(&mut reader)?);
    }

    Ok(snippets)
}
