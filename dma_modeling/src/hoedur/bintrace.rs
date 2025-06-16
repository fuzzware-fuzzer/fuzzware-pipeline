use crate::serialization_helpers::hex_u32;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::common::{Address, USize};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Access {
    pub target: AccessTarget,
    pub access_type: AccessType,
    pub size: u8,
    #[serde(serialize_with = "hex_u32")]
    pub pc: Address,
    #[serde(serialize_with = "hex_u32")]
    pub address: Address,
    #[serde(serialize_with = "hex_u32")]
    pub value: USize,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum AccessTarget {
    Ram,
    Mmio,
}
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum AccessType {
    Read,
    Write,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub events: Vec<TraceEvent>,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum TraceEvent {
    Access(Access),
}

impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} Access ({:?}) [ pc: {:08x}, size: {}, address: {:08x}, value: {:08x} ]",
            match self.target {
                AccessTarget::Ram => "RAM",
                AccessTarget::Mmio => "MMIO",
            },
            self.access_type,
            self.pc,
            self.size,
            self.address,
            self.value,
        )
    }
}

impl fmt::Display for Trace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for access in &self.events {
            match access {
                TraceEvent::Access(access) => writeln!(f, "{}", access),
            }
            .unwrap()
        }
        Ok(())
    }
}
