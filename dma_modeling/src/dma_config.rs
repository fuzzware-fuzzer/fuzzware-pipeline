use anyhow::{Context, Result};
use fxhash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};
use std::fs;
use std::{fs::File, io::BufWriter, path::PathBuf};

use crate::common::{Address, MmioAddress, RamAddress};
use crate::dma_analysis::{FieldTypeGuess, PointerType, SizeRange, POINTER_SIZE};
use crate::summary::DescriptorLayoutCandidate;

use crate::serialization_helpers::{hex_u32, is_empty_vec, is_false};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum SymbolizedValue {
    #[serde(serialize_with = "hex_u32")]
    Address(Address),
    Symbol(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DmaDescriptorPointer {
    #[serde(default, skip_serializing_if = "is_false")]
    is_buf_end_ptr: bool,
    #[serde(default, skip_serializing_if = "is_empty_vec")]
    known_values: Vec<SymbolizedValue>,

    to: Box<DmaDescriptorField>,
}

impl DmaDescriptorPointer {
    pub fn from_known_sizes(known_sizes: &FxHashMap<RamAddress, SizeRange>) -> Self {
        DmaDescriptorPointer {
            is_buf_end_ptr: false,
            known_values: known_sizes
                .keys()
                .map(|val| SymbolizedValue::Address(*val))
                .collect(),
            to: Box::new(DmaDescriptorField::Buffer(Default::default())),
        }
    }

    fn create_pointer_to_buffer(
        pointer: &PointerType,
        field_index: usize,
    ) -> DmaDescriptorFieldEntry {
        let buf_field_ptr_offset = field_index * POINTER_SIZE;

        let mut known_sizes: FxHashMap<RamAddress, u64> = Default::default();
        let is_buf_end_ptr = if pointer.potential_pre_buf_sizes.is_empty() {
            false
        } else {
            /* We are dealing with buffer end pointers. Collect the starts and unify their sizes */
            if pointer
                .potential_pre_buf_sizes
                .values()
                .any(|pre_buf_size| *pre_buf_size == 0)
            {
                false
            } else {
                for (buf_end_addr, pre_buf_size) in &pointer.potential_pre_buf_sizes {
                    let buf_start_addr = buf_end_addr + 1 - *pre_buf_size as u32;
                    known_sizes
                        .entry(buf_start_addr)
                        .and_modify(|cur_size| {
                            if *cur_size < *pre_buf_size {
                                *cur_size = *pre_buf_size;
                            }
                        })
                        .or_insert(*pre_buf_size);
                }
                true
            }
        };

        DmaDescriptorFieldEntry {
            descriptor: DmaDescriptorField::Pointer(DmaDescriptorPointer {
                known_values: if !is_buf_end_ptr {
                    pointer
                        .known_values
                        .iter()
                        .map(|known_addr| SymbolizedValue::Address(*known_addr))
                        .collect()
                } else {
                    Default::default()
                },
                to: Box::new(DmaDescriptorField::Buffer(Buffer {
                    known_sizes: known_sizes
                        .iter()
                        .map(|(buf_addr, size)| {
                            (
                                SymbolizedValue::Address(*buf_addr),
                                SizeRange {
                                    min: *size,
                                    max: *size,
                                },
                            )
                        })
                        .collect(),
                })),
                is_buf_end_ptr,
            }),
            offset: buf_field_ptr_offset,
        }
    }

    pub fn from_dma_descriptor(
        pointer_type: &PointerType,
        layout: &DescriptorLayoutCandidate,
        known_descr_addrs: &mut FxHashSet<RamAddress>,
    ) -> Self {
        let mut fields: Vec<DmaDescriptorFieldEntry> = Default::default();

        // Add buffer for dest pointer
        match &pointer_type.to[layout.dst_ptr_index] {
            FieldTypeGuess::Zero => {
                unreachable!("Require destination pointer to be set for descriptor (got: Zero)")
            }
            FieldTypeGuess::HighEntropy { .. } => unreachable!(
                "Require destination pointer to be set for descriptor (got: HighEntropy)"
            ),
            FieldTypeGuess::Pointer { pointer } => {
                fields.push(Self::create_pointer_to_buffer(
                    pointer,
                    layout.dst_ptr_index,
                ));
            }
        }

        // Add link pointers
        match layout.link_ptr_index {
            Some(link_ptr_index) => {
                if pointer_type.to.len() <= link_ptr_index {
                    // End of the chain (the type scan depth is exhausted)
                } else {
                    match &pointer_type.to[link_ptr_index] {
                        FieldTypeGuess::Zero => {
                            // End of the chain
                        }
                        FieldTypeGuess::HighEntropy { .. } => {
                            unreachable!("Not expecting to encounter a HighEntropy value as a link pointer...");
                        }
                        FieldTypeGuess::Pointer {
                            pointer: link_pointer,
                        } => {
                            known_descr_addrs.extend(&pointer_type.known_values);

                            if !link_pointer.to.is_empty()
                                && !known_descr_addrs.is_superset(&link_pointer.known_values)
                            {
                                // If we have a link, recursively specify the descriptors with known values
                                let link_field_offset = POINTER_SIZE * link_ptr_index;
                                fields.push(DmaDescriptorFieldEntry {
                                    offset: link_field_offset,
                                    descriptor: DmaDescriptorField::Pointer(
                                        Self::from_dma_descriptor(
                                            link_pointer,
                                            layout,
                                            known_descr_addrs,
                                        ),
                                    ),
                                });
                            }
                        }
                    }
                }
            }
            None => {
                // We have no links, do nothing further
            }
        }

        DmaDescriptorPointer {
            known_values: pointer_type
                .known_values
                .iter()
                .map(|val| SymbolizedValue::Address(*val))
                .collect(),
            to: Box::new(DmaDescriptorField::Descriptor({
                DmaDescriptor {
                    fields,
                    typedef: None,
                }
            })),
            is_buf_end_ptr: false,
        }
    }

    pub fn from_pointer_table(
        pointer_type: &PointerType,
        layout_per_offset: &FxHashMap<usize, DescriptorLayoutCandidate>,
    ) -> Self {
        let fields = layout_per_offset.iter().map(|(field_offset, descriptor_layout)| {
            let mut _tmp_descr_addrs = Default::default();
            DmaDescriptorFieldEntry {
                offset: *field_offset * POINTER_SIZE,
                descriptor: DmaDescriptorField::Pointer(Self::from_dma_descriptor(
                    match &pointer_type.to[*field_offset] {
                        FieldTypeGuess::Zero => unreachable!("Expecting active pointer table entries to not be always zero"),
                        FieldTypeGuess::HighEntropy { .. } => unreachable!("Expecting active pointer table entries to not be a HighEntropy value"),
                        FieldTypeGuess::Pointer { pointer } => pointer,
                    }, descriptor_layout, &mut _tmp_descr_addrs)),
            }
        }).collect();

        DmaDescriptorPointer {
            known_values: pointer_type
                .known_values
                .iter()
                .map(|val| SymbolizedValue::Address(*val))
                .collect(),
            to: Box::new(DmaDescriptorField::Descriptor({
                DmaDescriptor {
                    fields,
                    typedef: None,
                }
            })),
            is_buf_end_ptr: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DmaDescriptorFieldEntry {
    offset: usize,
    #[serde(flatten)]
    descriptor: DmaDescriptorField,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DmaDescriptorHead {
    #[serde(serialize_with = "hex_u32")]
    pub addr: Address,
    #[serde(flatten)]
    pub descriptor: DmaDescriptorPointer,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TypeDef {
    #[serde(rename = "type")]
    type_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    size: usize,
    mask: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DmaDescriptor {
    fields: Vec<DmaDescriptorFieldEntry>,
    #[serde(skip_serializing_if = "crate::serialization_helpers::is_none")]
    typedef: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Buffer {
    #[serde(
        default,
        skip_serializing_if = "crate::serialization_helpers::is_empty_map"
    )]
    known_sizes: FxHashMap<SymbolizedValue, SizeRange>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DmaDescriptorField {
    Pointer(DmaDescriptorPointer),
    Descriptor(DmaDescriptor),
    Buffer(Buffer),
    Status(Status),
    #[serde(untagged)]
    TypeDef(TypeDef),
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DmaConfig {
    #[serde(rename = "descriptors")]
    pub descriptor_heads: Vec<DmaDescriptorHead>,
    #[serde(
        default,
        skip_serializing_if = "crate::serialization_helpers::is_empty_map"
    )]
    pub known_sizes: FxHashMap<SymbolizedValue, SizeRange>,
}

impl DmaConfig {
    pub fn load(path: &PathBuf) -> Result<Self> {
        let config_raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read DMA config file: {:?}", path))?;

        // load main config
        let dma_config = serde_yaml::from_str(&config_raw)
            .with_context(|| format!("Failed to deserialize Fuzzware config file: {:?}", path))?;

        Ok(dma_config)
    }

    pub fn save(&self, out_path: &PathBuf) -> Result<()> {
        let writer: BufWriter<File> =
            BufWriter::new(File::create(out_path).with_context(|| {
                format!(
                    "Failed to open file for writing DMA config (does it exist?): {:?}",
                    out_path
                )
            })?);
        serde_yaml::to_writer(writer, self)
            .with_context(|| format!("Failed to write dma config {:?} to: {:?}", self, out_path))?;

        Ok(())
    }

    pub fn add_descriptor(&mut self, mmio_addr: MmioAddress, pointer: DmaDescriptorPointer) {
        self.descriptor_heads.push(DmaDescriptorHead {
            addr: mmio_addr,
            descriptor: pointer,
        });
    }

    pub fn add_known_buf_size(&mut self, buf_addr: RamAddress, size: SizeRange) {
        self.known_sizes
            .insert(SymbolizedValue::Address(buf_addr), size);
    }

    pub fn add_known_buf_sizes(&mut self, sizes: FxHashMap<RamAddress, SizeRange>) {
        for (buf_addr, size) in sizes {
            self.add_known_buf_size(buf_addr, size);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::fuzzware::fuzzware_dma_config::FuzzwareDmaConfig;
    use core::panic;

    use super::*;

    #[test]
    fn test_parse_dma_config() -> Result<()> {
        let trace_dir = std::env::current_exe()
            .unwrap()
            .ancestors()
            .skip(4)
            .next()
            .unwrap()
            .join("testdata/dma_configs");
        let dma_config_path = trace_dir.join("dma_config.yml");

        let dma_config = DmaConfig::load(&dma_config_path)?;

        println!("{:#x?}", dma_config);

        println!("###############################");

        let serialized = serde_yaml::to_string(&dma_config);

        println!("{}", serialized?);

        let fuzzware_dma_config_path = trace_dir.join("fuzzware_dma_config.yml");

        let dma_config = FuzzwareDmaConfig::load(&fuzzware_dma_config_path)?;

        println!("{:#x?}", dma_config);

        println!("###############################");

        let serialized = serde_yaml::to_string(&dma_config);

        println!("{}", serialized?);

        panic!();
    }
}
