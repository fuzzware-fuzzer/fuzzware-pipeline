use anyhow::Error;

use crate::common::Address;
use crate::fuzzware::fuzzware_config::FuzzwareConfig;
use std::fmt;
use std::path::PathBuf;

const MIN_ADDR: u32 = 0x8000;

#[derive(Debug, Clone)]
pub struct MemoryRange {
    start: Address,
    end: Address,
}

impl MemoryRange {
    pub fn contains(&self, addr: Address) -> bool {
        self.start <= addr && addr <= self.end
    }
}

#[derive(Clone, Debug)]
pub struct MemoryMap {
    pub ram_ranges: Vec<MemoryRange>,
    pub mmio_ranges: Vec<MemoryRange>,
}

impl MemoryMap {
    pub fn new(ram_ranges: Vec<(u32, u32)>, mmio_ranges: Vec<(u32, u32)>) -> Self {
        MemoryMap {
            ram_ranges: ram_ranges
                .into_iter()
                .map(|(start, end)| MemoryRange { start, end })
                .collect(),
            mmio_ranges: mmio_ranges
                .into_iter()
                .map(|(start, end)| MemoryRange { start, end })
                .collect(),
        }
    }

    pub fn is_mapped(&self, addr: Address) -> bool {
        self.is_mmio(addr) || self.is_ram(addr)
    }

    pub fn is_mmio(&self, addr: Address) -> bool {
        self.mmio_ranges.iter().any(|range| range.contains(addr))
    }

    pub fn is_ram(&self, addr: Address) -> bool {
        self.ram_ranges.iter().any(|range| range.contains(addr))
    }

    pub fn from_fuzzware_config(config_path: &PathBuf) -> Result<Self, Error> {
        let fuzzware_config = FuzzwareConfig::load(config_path)?;
        let fuzzware_mem_map = fuzzware_config.memory_map.unwrap();

        let mut mem_ranges: Vec<(u32, u32)> = Vec::new();
        let mut mmio_ranges: Vec<(u32, u32)> = Vec::new();
        for (name, entry) in fuzzware_mem_map.into_iter() {
            // Skip non-rw regions
            if !(entry.permissions.contains("r") && entry.permissions.contains("w")) {
                continue;
            }

            // Skip cortex-m regions
            if entry.address >= 0xe0000000 {
                continue;
            }

            // Skip too low addresses
            if entry.address <= MIN_ADDR {
                continue;
            }

            let l = if name.starts_with("mmio") {
                &mut mmio_ranges
            } else {
                &mut mem_ranges
            };
            l.push((entry.address, entry.address + entry.size))
        }

        Ok(Self::new(mem_ranges, mmio_ranges))
    }
}

impl fmt::Display for MemoryRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Range {:08x}-{:08x}", self.start, self.end)
    }
}

impl fmt::Display for MemoryMap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Ram ranges",)?;

        for range in &self.ram_ranges {
            writeln!(f, "{}", range)?
        }

        writeln!(f, "MMIO ranges",)?;

        for range in &self.mmio_ranges {
            writeln!(f, "{}", range)?
        }
        Ok(())
    }
}
