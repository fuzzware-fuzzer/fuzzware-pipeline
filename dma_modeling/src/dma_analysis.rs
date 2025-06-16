use crate::common::{Address, MmioAddress, RamAddress, TraceId};
use crate::dma_snippet::DmaAnalysisSnippet;
use crate::hoedur::bintrace::{Access, AccessTarget, AccessType, TraceEvent};
use crate::mem_map::MemoryMap;
use crate::mem_view::{MemoryHistory, MemoryView};
use crate::serialization_helpers::{hex_key, hex_set_vals, hex_u32, hex_u64};
use crate::Trace;
use anyhow::Error;
use endiannezz::Primitive;
use fxhash::{FxHashMap, FxHashSet};
use log::{debug, info, log_enabled, warn};
use serde::{Deserialize, Serialize};
use std::cmp::{max, min};
use std::ops::RangeBounds;
use std::usize;

pub const POINTER_SIZE: usize = 4;
pub const NULL: Address = 0;
pub const REQUIRED_POINTER_ALIGNMENT: Address = POINTER_SIZE as Address - 1;
const FIELD_SCAN_INITIAL_DEPTH: usize = 16;
/* Maximum assumed data structure complexity:
 * - Pointer to
 *  - List of Pointers in RAM pointing to
 *      - Descriptor which contains pointer to
 *          - DMA buffer
 * Other possible types are more shallow structures, e.g.:
 * - Pointer to
 *  - Descriptor which contains pointer to
 *      1. DMA buffer
 *      2. Next Descriptor
 */
const FIELD_SCAN_RECURSION_DEPTH: usize = 3;

// Initialization pattern constants
const MIN_INIT_PATTERN_LEN: usize = 2;
const MIN_INIT_PATTERN_LEN_COMPLEX_VALS: usize = 8;
const TRIVIAL_VALUES: [u64; 4] = [0, 0xff, 0xffff, 0xffffffff];

const MAX_INIT_PATTERN_SCAN_LEN: u32 = 0x800;
const MAX_UNINIT_LEN_PROFILE: u32 = 8;

const MAX_ACCESS_OFFSET: u32 = 4;

#[derive(Debug)]
struct BulkInitRange {
    start_addr: RamAddress,
    end_addr: RamAddress,
    start_ind: TraceId,
    end_ind: TraceId,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitPattern {
    #[serde(serialize_with = "hex_u64")]
    value: u64,
    pattern_len: usize,
    repetitions: usize,
    repetitions_before: usize, // Number of pattern repetitions before the buffer (if part of a bulk init)
}

#[derive(Debug, Serialize, Deserialize)]
pub enum InitializationState {
    // Latest write
    // Bulk init range
    Uninitialized {
        len: usize,
        // Number of uninitialized bytes before
        #[serde(default)]
        len_before: usize,
    },
    Pattern {
        latest_read_ind: Option<TraceId>,
        latest_write_ind: Option<TraceId>,
        at_config: InitPattern,
        at_bulk_init: Option<InitPattern>,
    },
    Used {
        latest_read_ind: Option<TraceId>,
        latest_write_ind: Option<TraceId>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AccessState {
    ReadBeforeWrite {
        #[allow(unused)]
        read_time: TraceId,
        #[allow(unused)]
        write_time: Option<TraceId>,
        #[allow(unused)]
        offset: Address,
    },
    WriteBeforeRead {
        #[allow(unused)]
        write_time: TraceId,
        #[allow(unused)]
        read_time: Option<TraceId>,
    },
    NoAccesses,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct AccessHistEntry {
    pub trace_ind: TraceId,
    pub access: Access,
}

pub struct TraceInfo {
    pub trace: Trace,
    pub mem: MemoryHistory,
    mem_map: MemoryMap,
    pub mmio_writes_by_addr: FxHashMap<MmioAddress, Vec<AccessHistEntry>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmaBufMeta {
    #[serde(serialize_with = "hex_u32")]
    pub mmio_address: MmioAddress,
    pub dma_buf: DmaBuf,
    #[serde(serialize_with = "hex_u32")]
    pub config_pc: Address,
    #[serde(serialize_with = "hex_u32")]
    pub access_pc: Address,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PointerCounterExample {
    UnalignedWrite {
        #[serde(serialize_with = "hex_u32")]
        address: Address,
        size: u8,
    },
    NonPointerWrite(#[serde(serialize_with = "hex_u32")] u32),
}

impl DmaBufMeta {
    pub fn merge_into(&mut self, other: &Self) -> bool {
        if self.mmio_address != other.mmio_address {
            return false;
        }

        for (known_buf_addr, other_size) in &other.dma_buf.known_sizes {
            match self.dma_buf.known_sizes.get_mut(known_buf_addr) {
                Some(own_size) => {
                    own_size.min = max(own_size.min, other_size.min);
                    own_size.max = min(own_size.max, other_size.max);
                }
                None => {
                    self.dma_buf
                        .known_sizes
                        .insert(*known_buf_addr, other_size.clone());
                }
            }
        }
        true
    }

    pub fn is_compatible_with(&self, _other: &Self) -> bool {
        true
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmaBuf {
    #[serde(serialize_with = "crate::serialization_helpers::hex_key")]
    pub known_sizes: FxHashMap<RamAddress, SizeRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SizeRange {
    #[serde(serialize_with = "hex_u64", alias = "min_size")]
    pub min: u64,
    #[serde(serialize_with = "hex_u64", alias = "max_size")]
    pub max: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TraceIdRange {
    #[serde(serialize_with = "hex_u32")]
    pub prev_id: TraceId,
    #[serde(serialize_with = "hex_u32")]
    pub curr_id: TraceId,
    #[serde(serialize_with = "hex_u32")]
    pub next_id: TraceId,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessStateProfile {
    pub has_read_before_write: bool,
    pub has_write_before_read: bool,
    pub has_no_access: bool,
}

/* Provide an explicit Default implementation to
avoid non-obvious issues when adding members */
impl Default for AccessStateProfile {
    fn default() -> Self {
        Self {
            has_read_before_write: false,
            has_write_before_read: false,
            has_no_access: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InitializationStateProfile {
    pub has_used: bool,
    pub has_pattern: bool,
    pub has_uninitialized: bool,
    pub all_writes_trivial: bool,
}

impl Default for InitializationStateProfile {
    fn default() -> Self {
        Self {
            has_used: false,
            has_pattern: false,
            has_uninitialized: false,
            all_writes_trivial: true,
        }
    }
}

impl InitializationStateProfile {
    fn new(init_state: &InitializationState) -> Self {
        Self {
            has_used: matches!(init_state, InitializationState::Used { .. }),
            has_pattern: matches!(init_state, InitializationState::Pattern { .. }),
            has_uninitialized: matches!(init_state, InitializationState::Uninitialized { .. }),
            all_writes_trivial: match init_state {
                InitializationState::Uninitialized { .. } => true,
                InitializationState::Pattern {
                    at_config,
                    at_bulk_init,
                    ..
                } => {
                    TRIVIAL_VALUES.contains(&at_config.value)
                        && match at_bulk_init {
                            Some(at_bulk_init) => TRIVIAL_VALUES.contains(&at_bulk_init.value),
                            None => true,
                        }
                }
                InitializationState::Used { .. } => false,
            },
        }
    }

    pub fn merge(&mut self, other: &Self) {
        self.has_used |= other.has_used;
        self.has_pattern |= other.has_pattern;
        self.has_uninitialized |= other.has_uninitialized;
        self.all_writes_trivial &= other.all_writes_trivial;
    }
}

impl AccessStateProfile {
    fn new(init_state: &AccessState) -> Self {
        Self {
            has_read_before_write: matches!(init_state, AccessState::ReadBeforeWrite { .. }),
            has_write_before_read: matches!(init_state, AccessState::WriteBeforeRead { .. }),
            has_no_access: matches!(init_state, AccessState::NoAccesses),
        }
    }

    pub fn merge(&mut self, other: &Self) {
        self.has_read_before_write |= other.has_read_before_write;
        self.has_write_before_read |= other.has_write_before_read;
        self.has_no_access |= other.has_no_access;
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct PointerType {
    #[serde(serialize_with = "hex_set_vals")]
    pub known_values: FxHashSet<RamAddress>,
    pub includes_mmio: bool,
    pub includes_misaligned_mmio: bool,
    pub includes_null: bool,
    pub to: Vec<FieldTypeGuess>,
    pub init_state_profile: InitializationStateProfile,
    pub access_state_profile: AccessStateProfile,
    #[serde(default, serialize_with = "hex_key")]
    pub potential_pre_buf_sizes: FxHashMap<RamAddress, u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum FieldTypeGuess {
    Zero,
    HighEntropy {
        #[serde(serialize_with = "hex_u32")]
        val: Address,
    },
    Pointer {
        pointer: PointerType,
    },
}

fn is_pointer_aligned(val: Address) -> bool {
    val & REQUIRED_POINTER_ALIGNMENT == 0
}

fn merge_field(own_field: &mut FieldTypeGuess, other_field: &FieldTypeGuess) -> bool {
    match own_field {
        FieldTypeGuess::Zero => {
            if !matches!(other_field, FieldTypeGuess::Zero) {
                *own_field = other_field.clone();
            }
        }
        FieldTypeGuess::HighEntropy { .. } => {
            // Nothing to be done, HighEntropy values always stay HighEntropy
        }
        FieldTypeGuess::Pointer { pointer } => {
            // For pointers, we need to
            // - For other pointers: also merge the de-referenced values
            // - For HighEntropy values: replace
            match other_field {
                FieldTypeGuess::Zero => pointer.includes_null = true,
                FieldTypeGuess::HighEntropy { .. } => *own_field = other_field.clone(),
                FieldTypeGuess::Pointer {
                    pointer: other_pointer,
                } => {
                    pointer.merge(other_pointer);
                }
            }
        }
    }

    true
}

fn merge_fields(own: &mut Vec<FieldTypeGuess>, other: &[FieldTypeGuess]) -> bool {
    for (i, field) in own.iter_mut().enumerate() {
        if let Some(other_field) = other.get(i) {
            merge_field(field, other_field);
        } else {
            // Out of fields in other field list
            break;
        }
    }

    true
}

impl PointerType {
    pub fn merge(&mut self, other: &Self) -> bool {
        /*
         * Merge the type information to its smallest common denominator.
         * We merge in the following priority:
         * - Zero: Weakest guess, always overwritten
         * - Pointer: Is compatible with, but overwrites Zero
         * - HighEntropy: Overwrites both Zero and Pointer types.
         */
        let mut merge_success = true;

        self.init_state_profile.merge(&other.init_state_profile);
        self.access_state_profile.merge(&other.access_state_profile);
        self.includes_misaligned_mmio |= other.includes_misaligned_mmio;
        self.includes_mmio |= other.includes_mmio;
        self.includes_null |= other.includes_null;

        // If we are solely an MMIO pointer, adopt the types from the other
        if self.known_values.is_empty() {
            assert!(self.includes_mmio);
            self.known_values = other.known_values.clone();
            self.potential_pre_buf_sizes = other.potential_pre_buf_sizes.clone();
        } else {
            self.known_values.extend(&other.known_values);

            for (other_addr, other_pre_buf_size) in &other.potential_pre_buf_sizes {
                self.potential_pre_buf_sizes
                    .entry(*other_addr)
                    .and_modify(|own_pre_buf_size| {
                        // For conflicting sizes, choose the minimum
                        *own_pre_buf_size = min(*own_pre_buf_size, *other_pre_buf_size);
                    })
                    .or_insert(*other_pre_buf_size);
            }
            merge_success = merge_fields(&mut self.to, &other.to);
        }

        merge_success
    }

    pub fn merge_field(&mut self, other_field: &FieldTypeGuess, field_ind: usize) -> bool {
        if let Some(own_field) = self.to.get_mut(field_ind) {
            merge_field(own_field, other_field)
        } else {
            false
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessAnalysisResult {
    pub trace_range: TraceIdRange,
    pub mmio_access: AccessHistEntry,
    pub init_state: InitializationState,
    pub access_state: AccessState,
    pub raw_type_guess: Option<PointerType>,
}

#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
pub struct RxTxPair {
    #[serde(serialize_with = "hex_u32")]
    pub ram_addr: RamAddress,
    #[serde(serialize_with = "hex_u32")]
    pub rx_reg: MmioAddress,
    #[serde(serialize_with = "hex_u32")]
    pub tx_reg: MmioAddress,
}

impl RxTxPair {
    pub fn create_reverse(&self) -> Self {
        RxTxPair {
            ram_addr: self.ram_addr,
            rx_reg: self.tx_reg,
            tx_reg: self.rx_reg,
        }
    }
}

impl TraceInfo {
    pub fn new(trace: Trace, mem_map: MemoryMap) -> Self {
        let mut res = TraceInfo {
            mmio_writes_by_addr: Default::default(),
            mem: Default::default(),
            trace,
            mem_map,
        };

        res.gen_trace_metadata();

        res
    }

    fn gen_trace_metadata(&mut self) {
        for (trace_ind, event) in self.trace.events.iter().enumerate() {
            match event {
                TraceEvent::Access(access) => {
                    match access.target {
                        AccessTarget::Ram => {
                            self.mem.add_access(trace_ind as TraceId, access);
                        }
                        AccessTarget::Mmio => {
                            match access.access_type {
                                AccessType::Read => {
                                    // Nothing to do with MMIO reads
                                }
                                AccessType::Write => self
                                    .mmio_writes_by_addr
                                    .entry(access.address)
                                    .or_default()
                                    .push({
                                        AccessHistEntry {
                                            trace_ind: trace_ind as TraceId,
                                            access: access.clone(),
                                        }
                                    }),
                            }
                        }
                    }
                }
            }
        }
    }
}

fn align_mmio_addr(address: u32) -> u32 {
    address & !(POINTER_SIZE as u32 - 1)
}

fn is_pattern(rep_count_before: usize, rep_count_after: usize, val: u64, val_size: usize) -> bool {
    let rep_count_total = rep_count_before + rep_count_after;

    if TRIVIAL_VALUES.contains(&val) {
        rep_count_total >= MIN_INIT_PATTERN_LEN
    } else {
        rep_count_total * val_size >= MIN_INIT_PATTERN_LEN_COMPLEX_VALS
    }
}

fn find_pattern_ux<
    T: RangeBounds<TraceId>,
    V: Primitive<Buf = [u8; N]> + Into<u64> + Eq,
    const N: usize,
>(
    mem_view: &MemoryView<T>,
    start: Address,
    end: Address,
    offset: Address,
) -> Option<InitPattern> {
    // check for 1-byte, 2-byte, and 4-byte patterns
    assert!(start <= end);
    assert!(offset <= end - start);
    if start + N as Address > end {
        return None;
    }

    let addr = start + offset;
    // check for unaligned offset
    if addr % N as Address != 0 {
        return None;
    }
    let len = end - start;
    let val: V = mem_view.read(addr)?;

    // Repetitions starting at offset
    let rep_count = (addr..end)
        .step_by(N)
        .into_iter()
        .position(|addr| mem_view.read::<V, N>(addr) != Some(val))
        .unwrap_or((len - offset) as usize);
    // Repetitions before offset
    let rep_count_before = (start..addr)
        .step_by(N)
        .into_iter()
        .rev()
        .position(|addr| mem_view.read::<V, N>(addr) != Some(val))
        .unwrap_or(offset as usize);

    if is_pattern(rep_count_before, rep_count, val.into(), N) {
        return Some(InitPattern {
            value: val.into(),
            pattern_len: N,
            repetitions: rep_count,
            repetitions_before: rep_count_before,
        });
    }

    None
}

fn find_pattern<T: RangeBounds<TraceId>>(
    mem_view: &MemoryView<T>,
    start: Address,
    end: Address,
    offset: Address,
) -> Option<InitPattern> {
    // check for 1-byte, 2-byte, and 4-byte patterns
    assert!(start <= end);
    assert!(offset <= end - start);
    if start == end {
        return None;
    }

    find_pattern_ux::<T, u8, 1>(mem_view, start, end, offset)
        .or_else(|| find_pattern_ux::<T, u16, 2>(mem_view, start, end, offset))
        .or_else(|| find_pattern_ux::<T, u32, 4>(mem_view, start, end, offset))
}

fn find_bulk_init_range(
    tinfo: &TraceInfo,
    address: u32,
    start_ind: TraceId,
    end_ind: TraceId,
) -> BulkInitRange {
    /* For a given point in time and address, we want to figure out
    whether an initialization of a larger buffer has taken place
    (which the current address is a part of).
    For this purpose, we scan forwards and backwards in the trace
    to see whether consecutive writes have been performed. */
    debug!(
        "find_bulk_init_range for address {:#x}, ind: {:#x} - {:#x}",
        address, start_ind, end_ind
    );
    let latest_write_entry = tinfo.mem.latest_write_at(address, end_ind).unwrap();
    let TraceEvent::Access(latest_write) =
        &tinfo.trace.events[latest_write_entry.trace_ind as usize];

    let mut curr_lower_address = latest_write.address;
    let mut curr_upper_address = latest_write.address + latest_write.size as u32;
    let mut curr_start_ind = latest_write_entry.trace_ind;
    let mut curr_end_ind = latest_write_entry.trace_ind;
    debug!("Starting with curr_lower_address {curr_lower_address:#x}, curr_upper_address {curr_upper_address:#x}, curr_start_ind {curr_start_ind:#x} , curr_end_ind {curr_end_ind:#x}. access: {latest_write:#x?}");

    // Scan backwards in the trace
    for (trace_offset, trace_entry) in tinfo.trace.events
        [start_ind as usize..latest_write_entry.trace_ind as usize]
        .iter()
        .rev()
        .enumerate()
    {
        let TraceEvent::Access(access) = trace_entry;
        if matches!(access.access_type, AccessType::Write) {
            debug!("[Backward, {trace_offset}] Got write access: {access:x?}");
            let addr = access.address;
            if addr == curr_upper_address {
                // Consecutive write to higher address
                curr_upper_address = addr + access.size as u32;
                debug!(
                    "-> Consecutive write (higher) -> curr_upper_address = {curr_upper_address:#x}"
                );
            } else if addr + access.size as u32 == curr_lower_address {
                // Consecutive write to lower address
                curr_lower_address = addr;
                debug!(
                    "-> Consecutive write (lower) -> curr_lower_address = {curr_lower_address:#x}"
                );
            } else {
                // Not a consecutive write, stop scanning
                debug!("-> Not consecutive, stopping");
                break;
            }
            curr_start_ind = latest_write_entry.trace_ind - trace_offset as TraceId - 1;
        } else {
            debug!("Skipping ")
        }
    }

    // Now scan forward in the trace
    for (trace_offset, trace_entry) in tinfo.trace.events
        [latest_write_entry.trace_ind as usize + 1..end_ind as usize]
        .iter()
        .enumerate()
    {
        let TraceEvent::Access(access) = trace_entry;
        if matches!(access.access_type, AccessType::Write) {
            debug!("[Forward, {trace_offset}] Got write access: {access:x?}");
            let addr = access.address;
            if addr == curr_upper_address {
                // Consecutive write to higher address
                curr_upper_address = addr + access.size as u32;
                debug!(
                    "-> Consecutive write (higher) -> curr_upper_address = {curr_upper_address:#x}"
                );
            } else if addr + access.size as u32 == curr_lower_address {
                // Consecutive write to lower address
                curr_lower_address = addr;
                debug!(
                    "-> Consecutive write (lower) -> curr_lower_address = {curr_lower_address:#x}"
                );
            } else {
                // Not a consecutive write, stop scanning
                debug!("-> Not consecutive, stopping");
                break;
            }
            curr_end_ind = latest_write_entry.trace_ind + trace_offset as TraceId + 1;
        }
    }

    BulkInitRange {
        start_addr: curr_lower_address,
        end_addr: curr_upper_address,
        start_ind: curr_start_ind,
        end_ind: curr_end_ind,
    }
}

fn get_initialization_state(
    tinfo: &TraceInfo,
    address: u32,
    start_ind: TraceId,
    end_ind: TraceId,
    max_num_inited: Address,
) -> InitializationState {
    // Initialization state before config
    info!("get_initialization_state: {address:#x} (time: {start_ind}-{end_ind})");

    // Check whether there are any writes in the first place
    let latest_write = tinfo.mem.get_u8_between(address, start_ind, end_ind);

    if latest_write.is_none() {
        // If we don't have any writes, check how many bytes are fully uninitialized
        let mem_view = tinfo.mem.mem_view_at(start_ind..end_ind);
        let num_uninited = (address..address + max_num_inited)
            .into_iter()
            .position(|address| mem_view.is_initialized(address))
            .unwrap_or(max_num_inited as usize);
        let num_uninited_before = (address - max_num_inited..address)
            .into_iter()
            .rev()
            .position(|address| mem_view.is_initialized(address))
            .unwrap_or(max_num_inited as usize);

        info!("Got {num_uninited} uninitialized bytes at buffer addr");
        assert!(
            num_uninited != 0,
            "For an uninitialized state, we expect at least the first byte to be uninitialized"
        );

        InitializationState::Uninitialized {
            len: num_uninited,
            len_before: num_uninited_before,
        }
    } else {
        // For the latest write to our potential buffer, we want to know whether it was part of a larger-region init (e.g., memset or stack initialization)
        let init_range = find_bulk_init_range(tinfo, address, start_ind, end_ind);
        info!("Found bulk initialization range: {:#x?}", init_range);

        let buf_bulk_init = tinfo
            .mem
            .mem_view_at(init_range.start_ind..=init_range.end_ind);

        let buf_at_config = tinfo.mem.mem_view_at(start_ind..end_ind);

        let latest_read_ind = tinfo
            .mem
            .latest_read_at(address, end_ind)
            .map(|entry| entry.trace_ind);
        let latest_write_ind = tinfo
            .mem
            .latest_write_at(address, end_ind)
            .map(|entry| entry.trace_ind);

        let pattern_bulk_init = find_pattern(
            &buf_bulk_init,
            init_range.start_addr,
            init_range.end_addr,
            (address - init_range.start_addr) as Address,
        );

        if let Some(at_config_init_pattern) = find_pattern(
            &buf_at_config,
            address,
            address + MAX_INIT_PATTERN_SCAN_LEN,
            0,
        ) {
            return InitializationState::Pattern {
                at_bulk_init: pattern_bulk_init,
                latest_read_ind,
                latest_write_ind,
                at_config: at_config_init_pattern,
            };
        }

        InitializationState::Used {
            latest_read_ind,
            latest_write_ind,
        }
    }
}

fn get_access_state<T: RangeBounds<TraceId>>(
    tinfo: &TraceInfo,
    address: u32,
    time: T,
) -> AccessState {
    for offset in 0..MAX_ACCESS_OFFSET {
        // Search for read-before-write after access
        let next_read = tinfo.mem.next_read(address + offset, &time);
        let next_write = tinfo.mem.next_write(address + offset, &time);

        match (next_read, next_write) {
            (Some(read), None) => {
                // Only read, no write
                info!("Got read {read:#x?}, no write");

                let TraceEvent::Access(Access {
                    size: read_size, ..
                }) = tinfo.trace.events[read.trace_ind as usize];
                if offset >= 2 * read_size as Address {
                    return AccessState::NoAccesses;
                }

                return AccessState::ReadBeforeWrite {
                    read_time: read.trace_ind,
                    write_time: None,
                    offset,
                };
            }
            (Some(read), Some(write)) => {
                info!("Got read {read:#x?}, write {write:#x?}");

                let TraceEvent::Access(Access {
                    size: read_size, ..
                }) = tinfo.trace.events[read.trace_ind as usize];
                if offset >= 2 * read_size as Address {
                    return AccessState::NoAccesses;
                } else {
                    let TraceEvent::Access(Access {
                        size: write_size, ..
                    }) = tinfo.trace.events[write.trace_ind as usize];
                    if offset >= 2 * write_size as Address {
                        return AccessState::NoAccesses;
                    }
                }

                if read.trace_ind < write.trace_ind {
                    return AccessState::ReadBeforeWrite {
                        read_time: read.trace_ind,
                        write_time: Some(write.trace_ind),
                        offset,
                    };
                } else {
                    return AccessState::WriteBeforeRead {
                        write_time: write.trace_ind,
                        read_time: Some(read.trace_ind),
                    };
                }
            }
            (None, Some(write)) => {
                info!("No read, but write {write:#x?}");

                let TraceEvent::Access(Access {
                    size: write_size, ..
                }) = tinfo.trace.events[write.trace_ind as usize];
                if offset >= 2 * write_size as Address {
                    return AccessState::NoAccesses;
                }

                return AccessState::WriteBeforeRead {
                    write_time: write.trace_ind,
                    read_time: None,
                };
            }
            (None, None) => {
                info!("Got no accesses at all at offset {offset}...");
            }
        }
    }

    AccessState::NoAccesses
}

fn gather_type_info_recursive(
    tinfo: &TraceInfo,
    ram_address: RamAddress,
    trace_ind: TraceId,
    prev_ind: TraceId,
    next_ind: TraceId,
    remaining_depth: usize,
    init_state_cache: &mut InitStateCache,
) -> Vec<FieldTypeGuess> {
    if remaining_depth == 0 {
        Default::default()
    } else {
        /* Assumptions
         * 1. Descriptors are fully set up at the point in time where descriptor pointer is written to MMIO
         * 2. Type restrictions on the values always hold upon write to MMIO register (finding a counterexample
         *    to a type can be used to eliminate type / type info can be merged between all runs)
         */

        // Plan:
        // 1. Read u32 values AT TIME OF MMIO register write
        // 2. Check the u32 values for types
        // 3. Follow Pointer types recursively (up to certain depth)

        let mem_view = tinfo.mem.mem_view_at(0..trace_ind);

        let res: Vec<FieldTypeGuess> = (ram_address..ram_address + ((FIELD_SCAN_INITIAL_DEPTH * POINTER_SIZE as usize) as Address)).into_iter().step_by(POINTER_SIZE)
            .map(|ram_addr| {
                let mut value: Address = mem_view.read(ram_addr).unwrap_or(0);
                if value == 0 {
                    // For potentially uninitialized NULL values, merge the next write into the type
                    let maybe_write_accesses =
                        tinfo.mem.get_writes_between(ram_addr, trace_ind, next_ind);
                    match maybe_write_accesses {
                        Some(writes) => {
                            let mut it = writes.iter();
                            if let Some(entry) = it.next() {
                                // We have at least one more write, get the correct timing of reading the u32 in case a value is written byte-wise
                                value = if let Some(next_entry) = it.next() {
                                    // We have a next write to the same address, take the first u32 at the time just before that write
                                    tinfo.mem.mem_view_at(
                                        entry.trace_ind..next_entry.trace_ind,
                                    )
                                } else {
                                    // We have no next write to the same address, take the latest u32
                                    tinfo.mem.mem_view_at(
                                        entry.trace_ind..next_ind,
                                    )
                                }
                                .read(ram_addr).unwrap_or(0)
                            }
                        }
                        None => {
                            // No other values, value stays zero
                        }
                    }
                };

                if value == 0 {
                    FieldTypeGuess::Zero
                } else {
                    let is_ram_addr = tinfo.mem_map.is_ram(value);
                    let is_mmio_addr = !is_ram_addr && tinfo.mem_map.is_mmio(value);

                    if is_ram_addr || is_mmio_addr {
                        let access_state_profile;
                        let init_state_profile;
                        let mut potential_pre_buf_size: Option<usize> = None;

                        if is_ram_addr {
                            let init_state = init_state_cache.get(value, prev_ind, trace_ind);

                            let access_state = get_access_state(
                                tinfo,
                                value,
                                trace_ind..next_ind,
                            );

                            access_state_profile = AccessStateProfile::new(&access_state);
                            init_state_profile = InitializationStateProfile::new(&init_state);

                            if value & 1 == 0 {
                                // Consider only unaligned pointers as potential end-of-buffer pointers
                                potential_pre_buf_size = Some(usize::MIN);
                            } else {
                                // For unaligned pointers, we try to find whether this may be a pointer
                                // to the END of a DMA buffer.
                                // The idea here is to check that we have accesses to the location before
                                // what we are pointing to. We also check that all locations within the
                                // potential buffer are uninitialized or read from in an uninitialized manner

                                // char buf[8];
                                // buf[0]
                                // buf[1]
                                // buf[2]
                                // buf[3]
                                // ...
                                // buf[7] <-

                                // check that the following conditions hold true:
                                // 1. All writes-before-first-read have primitive values
                                // 2. Then we have an uninitialized read
                                // 3. For all positions between the supposed end of the buffer and the first read, all is uninitialized
                                // 4. When the first uninit read position is found, scan backwards to the first
                                //    offset where there is no uninitialized read / no read at all. This marks the start of the buffer
                                info!("Considering buffer end pointer for address: {value:#x}.\nInit state: {init_state:#x?}\nAccess state: {access_state:#x?}");

                                let uninit_pre_len = match &init_state {
                                    InitializationState::Uninitialized { len_before, .. } => *len_before,
                                    InitializationState::Pattern { at_bulk_init, .. } => {
                                        if let Some(at_bulk_init) = at_bulk_init {
                                            if at_bulk_init.value != 0 || at_bulk_init.pattern_len != 1 {
                                                // Only consider this for zeroed buffers
                                                0
                                            } else {
                                                at_bulk_init.repetitions_before
                                            }
                                        } else {
                                            // No bulk initialization found: Do not consider
                                            0
                                        }
                                    },
                                    InitializationState::Used { .. } => {
                                        // Don't consider used buffers
                                        0
                                    },
                                };

                                if uninit_pre_len == 0 {
                                    // We did not find a valid bulk initialization, do not consider
                                    potential_pre_buf_size = None;
                                } else {
                                    let mut first_read_offset= usize::MAX;
                                    // Skip unread and find first read
                                    for offset in 0 ..= uninit_pre_len {
                                        let cursor_addr = value - offset as u32;

                                        if tinfo.mem.reads.contains_key(&cursor_addr) {
                                            // We found our first read!
                                            // Scan further to see how many bytes are also accessed in an uninitialized manner
                                            first_read_offset = offset;
                                            break;
                                        } else {
                                            // No reads: Go on to next previous buffer location
                                            continue;
                                        }
                                    }

                                    if first_read_offset == usize::MAX {
                                        // Found no read
                                        potential_pre_buf_size = None;
                                    } else {
                                        // We have a read. Scan backwards to find start of buffer
                                        for offset in first_read_offset ..= uninit_pre_len {
                                            let cursor_addr = value - offset as u32;

                                            if tinfo.mem.reads.contains_key(&cursor_addr) {
                                                // We found another read: Continue scanning
                                                // Scan further to see how many bytes are also accessed in an uninitialized manner
                                                potential_pre_buf_size.replace(offset + 1);
                                                continue;
                                            } else {
                                                // No reads: We found the first entry not belonging to the buffer
                                                break;
                                            }
                                        }
                                        // If we did not break
                                    }
                                }
                            }
                        } else {
                            access_state_profile = Default::default();
                            init_state_profile = Default::default();
                            // For MMIO addresses, no we can have no buffer
                            potential_pre_buf_size = Some(usize::MIN);
                        }

                        FieldTypeGuess::Pointer {
                            pointer: PointerType {
                                known_values: if is_ram_addr {
                                    FxHashSet::from_iter([value])
                                } else {
                                    Default::default()
                                },
                                to: if is_ram_addr {
                                    gather_type_info_recursive(
                                        tinfo,
                                        value,
                                        trace_ind,
                                        prev_ind,
                                        next_ind,
                                        remaining_depth - 1,
                                        init_state_cache,
                                    )
                                } else {
                                    Vec::new()
                                },
                                includes_mmio: is_mmio_addr,
                                includes_null: false,
                                includes_misaligned_mmio: is_mmio_addr && !is_pointer_aligned(value),
                                init_state_profile,
                                access_state_profile,
                                potential_pre_buf_sizes: match potential_pre_buf_size {
                                    Some(pre_buf_size) => FxHashMap::from_iter([(value, pre_buf_size as u64)]),
                                    None => Default::default(),
                                }
                            },
                        }
                    } else {
                        FieldTypeGuess::HighEntropy { val: value }
                    }
                }
            })
            .collect();

        res
    }
}

struct InitStateCache<'a> {
    cache: FxHashMap<RamAddress, InitializationState>,
    start_ind: TraceId,
    end_ind: TraceId,
    tinfo: &'a TraceInfo,
    max_uninit_len: Address,
}

impl<'a> InitStateCache<'a> {
    pub fn new(
        tinfo: &'a TraceInfo,
        max_uninit_len: Address,
        start_ind: TraceId,
        end_ind: TraceId,
    ) -> Self {
        Self {
            cache: Default::default(),
            start_ind,
            end_ind,
            tinfo,
            max_uninit_len,
        }
    }

    pub fn get(
        &mut self,
        ram_address: RamAddress,
        start_ind: TraceId,
        end_ind: TraceId,
    ) -> &InitializationState {
        debug_assert_eq!(self.start_ind, start_ind);
        debug_assert_eq!(self.end_ind, end_ind);

        self.cache.entry(ram_address).or_insert_with(|| {
            get_initialization_state(
                self.tinfo,
                ram_address,
                self.start_ind,
                self.end_ind,
                self.max_uninit_len,
            )
        })
    }
}

fn gather_type_info(
    tinfo: &TraceInfo,
    ram_address: RamAddress,
    trace_ind: TraceId,
    prev_ind: TraceId,
    next_ind: TraceId,
    init_state_cache: &mut InitStateCache,
) -> PointerType {
    // We could add some restrictions on that. E.g., we only consider writes to Zero'ed regions / uninitialized regions
    // The restriction could also be that there is only a single write of the pointer to the MMIO register
    // (which would indicate a static location)

    PointerType {
        known_values: FxHashSet::from_iter([ram_address]),
        to: gather_type_info_recursive(
            tinfo,
            ram_address,
            trace_ind,
            prev_ind,
            next_ind,
            FIELD_SCAN_RECURSION_DEPTH,
            init_state_cache,
        ),
        includes_mmio: false,
        includes_misaligned_mmio: false,
        includes_null: false,
        init_state_profile: InitializationStateProfile::new(init_state_cache.get(
            ram_address,
            prev_ind,
            trace_ind,
        )),
        access_state_profile: AccessStateProfile::new(&get_access_state(
            tinfo,
            ram_address,
            trace_ind..next_ind,
        )),
        potential_pre_buf_sizes: Default::default(),
    }
}

pub fn detect_dma(mem_map: MemoryMap, trace: Trace) -> Result<DmaAnalysisSnippet, Error> {
    let tinfo = TraceInfo::new(trace, mem_map);

    let mut mmio_written_ram_addrs: FxHashMap<MmioAddress, Vec<AccessHistEntry>> =
        Default::default();

    let mut mmio_non_pointers: FxHashMap<MmioAddress, PointerCounterExample> = Default::default();
    let mut misaligned_mmio_ram_addr_writes: FxHashMap<MmioAddress, Access> = Default::default();
    let mut mmio_regs_with_mmio_ptr_writes: FxHashSet<MmioAddress> = Default::default();

    // 1. Get mmio-written RAM addresses
    for (mmio_address, accesses) in tinfo.mmio_writes_by_addr.iter() {
        let aligned_addr = align_mmio_addr(*mmio_address);
        if *mmio_address != aligned_addr {
            mmio_non_pointers.entry(aligned_addr).or_insert_with(|| {
                let access = &accesses[0].access;
                PointerCounterExample::UnalignedWrite {
                    address: access.address,
                    size: access.size,
                }
            });

            // For unaligned addresses, also add any overlapped-into addresses
            for entry in accesses {
                let access = &entry.access;
                mmio_non_pointers
                    .entry(align_mmio_addr(mmio_address + access.size as u32 - 1))
                    .or_insert_with(|| PointerCounterExample::UnalignedWrite {
                        address: access.address,
                        size: access.size,
                    });
            }

            continue;
        }

        // Ensure that all writes are aligned and pointing at RAM

        let mut found_ram_ptr = false;
        let mut found_mmio_ptr = false;
        let has_non_pointer_writes = accesses.iter().any(|AccessHistEntry { trace_ind, access }| {
            if access.size as usize != POINTER_SIZE {
                info!("Aligned MMIO address: {:#08x} access ind {:#04x} has a non-pointer-sized access (size: {})", mmio_address, trace_ind, access.size);
                mmio_non_pointers.entry(*mmio_address).or_insert_with(|| {
                    PointerCounterExample::UnalignedWrite { address: access.address, size: access.size }
                });
                true
            } else if access.value == NULL {
                // Ignore NULL pointer writes
                false
            } else if tinfo.mem_map.is_mmio(access.value) {
                found_mmio_ptr = true;
                false
            } else if tinfo.mem_map.is_ram(access.value) {
                found_ram_ptr = true;
                if !is_pointer_aligned(access.value) {
                    misaligned_mmio_ram_addr_writes.entry(*mmio_address).or_insert_with(|| access.clone());
                }
                false
            } else {
                info!("Aligned MMIO address: {:#08x} access ind {:#04x} has a non-pointer write (value: {:#08x})", mmio_address, trace_ind, access.value);
                mmio_non_pointers.entry(*mmio_address).or_insert_with(|| {
                    PointerCounterExample::NonPointerWrite(access.value)
                });
                true
            }
        });

        if has_non_pointer_writes {
            info!(
                "Aligned MMIO address: {:#08x} has a non-aligned or non-ram write",
                mmio_address
            );
            continue;
        }

        if found_mmio_ptr {
            mmio_regs_with_mmio_ptr_writes.insert(*mmio_address);
        }

        if !found_ram_ptr {
            info!(
                "Aligned MMIO address: {:#08x} did not find any RAM writes",
                mmio_address
            );
            continue;
        }

        // All conditions for RAM address write are fulfilled
        mmio_written_ram_addrs.insert(
            *mmio_address,
            accesses
                .iter()
                .filter(|x| x.access.value != 0)
                .cloned()
                .collect(),
        );
    }

    info!(
        "Got {} MMIO written RAM addresses",
        mmio_written_ram_addrs.len()
    );

    if log_enabled!(log::Level::Info) {
        for (mmio_addr, pointer_write_accesses) in mmio_written_ram_addrs.iter() {
            for pointer_write in pointer_write_accesses {
                // Unwrap: Trace is guaranteed to have the entry as we have found it above
                let ev = tinfo
                    .trace
                    .events
                    .get(pointer_write.trace_ind as usize)
                    .unwrap();
                let pc = match ev {
                    TraceEvent::Access(access) => access.pc,
                };
                info!(
                    "{}: [{:#08x}] {:08x} = {:08x}",
                    pointer_write.trace_ind, pc, mmio_addr, pointer_write.access.value
                );
            }
        }
    }

    let mut analysis_by_mmio_addr: FxHashMap<MmioAddress, Vec<AccessAnalysisResult>> =
        Default::default();
    let mut analysis_by_ram_addr: FxHashMap<RamAddress, FxHashSet<MmioAddress>> =
        Default::default();

    let mut guessed_type_by_mmio_addr: FxHashMap<MmioAddress, PointerType> = Default::default();
    let mut init_state_profile_by_mmio_addr: FxHashMap<MmioAddress, InitializationStateProfile> =
        Default::default();
    let mut access_state_profile_by_mmio_addr: FxHashMap<MmioAddress, AccessStateProfile> =
        Default::default();

    for (mmio_addr, writes) in mmio_written_ram_addrs.iter() {
        let mut prev_trace_ind_by_ram_addr: FxHashMap<RamAddress, TraceId> = Default::default();
        let mut prev_trace_ind;
        let mut it = writes.iter().peekable();

        let mut consider_ram_descriptor = !misaligned_mmio_ram_addr_writes.contains_key(mmio_addr)
            && !mmio_regs_with_mmio_ptr_writes.contains(mmio_addr);
        let mut overall_guessed_type: Option<PointerType> = Default::default();

        let mut init_profile: InitializationStateProfile = Default::default();
        let mut access_profile: AccessStateProfile = Default::default();

        while let Some(AccessHistEntry { trace_ind, access }) = it.next() {
            let next_trace_ind = it.peek().map_or(TraceId::MAX, |x| x.trace_ind);
            let ram_address = access.value;
            assert!(next_trace_ind > *trace_ind);

            prev_trace_ind = prev_trace_ind_by_ram_addr
                .get(&ram_address)
                .map(|v| *v)
                .unwrap_or(0 as TraceId);

            let init_state: InitializationState = get_initialization_state(
                &tinfo,
                ram_address,
                prev_trace_ind,
                *trace_ind,
                MAX_INIT_PATTERN_SCAN_LEN,
            );
            init_profile.merge(&InitializationStateProfile::new(&init_state));

            info!(
                "Got initialization state for trace ind {:#x}, addr {:#x}: {:#x?}",
                trace_ind, ram_address, init_state
            );

            let access_state = get_access_state(&tinfo, ram_address, *trace_ind..next_trace_ind);
            info!(
                "Got access state for trace ind {:#x}, addr {:#x}: {:#x?}",
                trace_ind, ram_address, access_state
            );
            access_profile.merge(&AccessStateProfile::new(&access_state));

            let mut init_state_cache =
                InitStateCache::new(&tinfo, MAX_UNINIT_LEN_PROFILE, prev_trace_ind, *trace_ind);

            let mut cur_type_guess: Option<PointerType> = None;
            if consider_ram_descriptor {
                let mut cur_pointer_guess = gather_type_info(
                    &tinfo,
                    ram_address,
                    *trace_ind,
                    prev_trace_ind,
                    next_trace_ind,
                    &mut init_state_cache,
                );

                info!("Gathering potential pointer table for MMIO addr: {mmio_addr:#x}");
                let table_types = gather_pointer_table_types(
                    &tinfo,
                    ram_address,
                    &cur_pointer_guess,
                    *trace_ind,
                    prev_trace_ind,
                    next_trace_ind,
                );

                if !table_types.is_empty() {
                    info!("Got {} table pointer types:", table_types.len());
                }

                for (i, pointer) in table_types.into_iter().enumerate() {
                    info!("[{i}] Merging pointer table type: {pointer:#x?}");
                    cur_pointer_guess.merge_field(&FieldTypeGuess::Pointer { pointer: pointer }, i);
                }

                if let Some(cur_type_guess_summary) = &mut overall_guessed_type {
                    if !cur_type_guess_summary.merge(&cur_pointer_guess) {
                        warn!("Could not merge {cur_pointer_guess:#x?} into {cur_type_guess_summary:#x?}");
                        consider_ram_descriptor = false;
                        overall_guessed_type = None;
                    }
                } else {
                    overall_guessed_type = Some(cur_pointer_guess.clone());
                }

                cur_type_guess = Some(cur_pointer_guess);
            }

            let analysis_result = AccessAnalysisResult {
                trace_range: TraceIdRange {
                    prev_id: prev_trace_ind,
                    curr_id: *trace_ind,
                    next_id: next_trace_ind,
                },
                mmio_access: AccessHistEntry {
                    trace_ind: *trace_ind,
                    access: access.clone(),
                },
                init_state,
                access_state,
                raw_type_guess: cur_type_guess,
            };

            analysis_by_mmio_addr
                .entry(*mmio_addr)
                .or_default()
                .push(analysis_result);

            analysis_by_ram_addr
                .entry(ram_address)
                .or_default()
                .insert(*mmio_addr);

            prev_trace_ind_by_ram_addr.insert(ram_address, *trace_ind);
        }
        if let Some(overall_guessed_type) = overall_guessed_type {
            guessed_type_by_mmio_addr.insert(*mmio_addr, overall_guessed_type);
        }
        init_state_profile_by_mmio_addr.insert(*mmio_addr, init_profile);
        access_state_profile_by_mmio_addr.insert(*mmio_addr, access_profile);
    }

    let mut dma_buf_ptr_candidates: FxHashMap<MmioAddress, DmaBufMeta> = Default::default();
    let mut ambiguous_candidate_mmio_addrs: FxHashSet<_> = Default::default();

    let rx_tx_pairs: FxHashMap<MmioAddress, RxTxPair> =
        find_rx_tx_pairs(&analysis_by_mmio_addr, &analysis_by_ram_addr);

    for (mmio_addr, analysis_results) in analysis_by_mmio_addr.iter() {
        let (is_considered_rx, is_considered_tx) = match rx_tx_pairs.get(mmio_addr) {
            Some(reg_pair) => (*mmio_addr == reg_pair.rx_reg, *mmio_addr == reg_pair.tx_reg),
            None => (false, false),
        };

        if is_considered_tx {
            info!("Skipping analysis for TX-considered MMIO reg {mmio_addr:#x}");
            continue;
        }

        // Unwrap: We have at least one MMIO write for each analysis result
        let init_state_profile = init_state_profile_by_mmio_addr.get(mmio_addr).unwrap();
        if init_state_profile.has_used && !is_considered_rx {
            info!("Skipping analysis for MMIO reg which has a used entry");
            continue;
        }

        // Detect pointers from MMIO registers directly to DMA buffers
        for res in analysis_results {
            match &res.init_state {
                InitializationState::Used { .. } => {
                    // For used buffers, check whether the MMIO register is considered an RX register in an rx/tx pair
                    if !is_considered_rx {
                        continue;
                    }
                    info!("Processing MMIO analysis even though it references a used buffer as it is considered an RX buffer in an RX/TX pair: {mmio_addr:#x}");
                }
                InitializationState::Pattern { .. } => (),
                InitializationState::Uninitialized { .. } => (),
            }

            match res.access_state {
                AccessState::ReadBeforeWrite { .. } => (),
                AccessState::WriteBeforeRead { .. } => continue,
                AccessState::NoAccesses => continue,
            }

            let new_buf_ptr = DmaBufMeta {
                mmio_address: *mmio_addr,
                dma_buf: DmaBuf {
                    known_sizes: FxHashMap::from_iter([(
                        res.mmio_access.access.value,
                        SizeRange {
                            min: 1,
                            max: match &res.init_state {
                                InitializationState::Uninitialized { len, .. } => *len as u64,
                                InitializationState::Pattern {
                                    at_config:
                                        InitPattern {
                                            pattern_len,
                                            repetitions,
                                            ..
                                        },
                                    ..
                                } => (pattern_len * repetitions) as u64,
                                InitializationState::Used { .. } => {
                                    // For rx buffers from rx/tx pairs, let the buffer grow linearly
                                    u64::MAX
                                }
                            },
                        },
                    )]),
                },
                config_pc: res.mmio_access.access.pc,
                access_pc: match res.access_state {
                    AccessState::ReadBeforeWrite { read_time, .. } => {
                        let TraceEvent::Access(access) = &tinfo.trace.events[read_time as usize];
                        access.pc
                    }
                    AccessState::WriteBeforeRead { .. } => unreachable!(),
                    AccessState::NoAccesses => unreachable!(),
                },
            };

            if let Some(existing_buf) = dma_buf_ptr_candidates.get_mut(&mmio_addr) {
                // Merge Descriptor Entries
                if !existing_buf.merge_into(&new_buf_ptr) {
                    ambiguous_candidate_mmio_addrs.insert(*mmio_addr);
                }
            } else {
                dma_buf_ptr_candidates.insert(*mmio_addr, new_buf_ptr);
            }
        }

        // Detect pointers from MMIO registers to potential RAM-based DMA descriptors
        if is_considered_rx {
            info!("Skipping RAM-based DMA descriptor analysis for RX-considered MMIO reg {mmio_addr:#x}");
            continue;
        }

        if let Some(access) = misaligned_mmio_ram_addr_writes.get(mmio_addr) {
            info!("Skipping RAM-based DMA descriptor analysis for MMIO reg {mmio_addr:#x}. Access: {access:#x?}");
            continue;
        }

        if mmio_regs_with_mmio_ptr_writes.contains(mmio_addr) {
            info!("Skipping RAM-based DMA descriptor analysis for MMIO reg {mmio_addr:#x} as we found an MMIO pointer write to it");
            continue;
        }
    }

    let mut collided_dma_descriptors: Vec<DmaBufMeta> = Default::default();

    let mut res = DmaAnalysisSnippet::default();

    for (mmio_addr, descr) in dma_buf_ptr_candidates {
        if ambiguous_candidate_mmio_addrs.contains(&mmio_addr) {
            collided_dma_descriptors.push(descr);
        } else if mmio_non_pointers.contains_key(&mmio_addr) {
            res.discarded_candidates.push(descr);
        } else {
            res.detected_candidates.insert(mmio_addr, descr);
        }
    }

    info!("Got {} analysis results", analysis_by_mmio_addr.len());
    info!("{:#x?}", analysis_by_mmio_addr);

    res.mmio_pointer_counterexamples = mmio_non_pointers;
    res.analysis_by_mmio_addr = analysis_by_mmio_addr;
    res.collided_descriptors = collided_dma_descriptors;
    res.ambiguous_candidate_mmio_addrs = ambiguous_candidate_mmio_addrs.into_iter().collect();
    res.misaligned_mmio_writes = misaligned_mmio_ram_addr_writes;
    res.guessed_type_by_mmio_addr = guessed_type_by_mmio_addr;
    res.set_rx_tx_pairs(&rx_tx_pairs);

    info!(
        "Got {} ambiguous DMA descriptor MMIO addresses:",
        res.ambiguous_candidate_mmio_addrs.len()
    );
    info!("{:#x?}", res.ambiguous_candidate_mmio_addrs);

    info!(
        "Got {} DMA description definitions with pointer counterexamples",
        res.discarded_candidates.len()
    );
    info!("{:#x?}", res.discarded_candidates);

    info!(
        "Got {} valid detected DMA buffers",
        res.detected_candidates.len()
    );
    info!("{:#x?}", res.detected_candidates);

    Ok(res)
}

fn gather_pointer_table_types(
    tinfo: &TraceInfo,
    ram_address: u32,
    cur_pointer_guess: &PointerType,
    trace_ind: TraceId,
    prev_ind: TraceId,
    next_ind: TraceId,
) -> Vec<PointerType> {
    let mut table_types: Vec<PointerType> = Default::default();
    let mut init_state_cache =
        InitStateCache::new(tinfo, MAX_UNINIT_LEN_PROFILE, prev_ind, trace_ind);

    // Only allow such pointer tables to be set up once
    if prev_ind != 0 || next_ind != TraceId::MAX {
        info!("Pointer table identification: Multiple table pointer writes found, not considering an additional type");
        return table_types;
    }

    // Scan fields for pointers until a NULL / non-pointer field is found. For each field:
    // 1. Iterate over all writes to the field
    // 2. For each write, check whether it is
    //      a) NULL
    //      b) Collect type info (and merge)

    'outer: for (i, field_type) in cur_pointer_guess.to.iter().enumerate() {
        assert_eq!(i, table_types.len());
        let mut is_init_null = false;

        match field_type {
            FieldTypeGuess::Zero => is_init_null = true,
            FieldTypeGuess::HighEntropy { .. } => break,
            FieldTypeGuess::Pointer { pointer } => {
                table_types.push(pointer.clone());
            }
        }

        let potential_pointer_field_addr: RamAddress =
            ram_address + (i * POINTER_SIZE) as RamAddress;

        let maybe_write_accesses =
            tinfo
                .mem
                .get_writes_between(potential_pointer_field_addr, trace_ind, next_ind);
        match maybe_write_accesses {
            None => {
                if is_init_null {
                    // Got NULL and no further writes, potential pointer table is NULL-terminated
                    break;
                } else {
                    // Got pointer and no further writes, keep going with next field
                    continue;
                }
            }
            Some(write_accesses) if write_accesses.is_empty() => {
                if is_init_null {
                    // Got NULL and no further writes, potential pointer table is NULL-terminated
                    break;
                } else {
                    // Got pointer and no further writes, keep going with next field
                    continue;
                }
            }
            Some(write_accesses) => {
                for entry in write_accesses {
                    let write_trace_ind = entry.trace_ind;
                    assert!(write_trace_ind <= next_ind);
                    let val = tinfo
                        .mem
                        .get_u32_at(potential_pointer_field_addr, write_trace_ind)
                        .unwrap_or(NULL);

                    if val == NULL {
                        info!("[{i:#02x}] Got NULL write at field offset {i} (addr offset: {:#x}), stopping", i * POINTER_SIZE);
                        break 'outer;
                    } else if tinfo.mem_map.is_ram(val) && is_pointer_aligned(val) {
                        let cur_type = gather_type_info(
                            tinfo,
                            val,
                            write_trace_ind,
                            prev_ind,
                            next_ind,
                            &mut init_state_cache,
                        );
                        info!("[{i:#02x}] Got RAM pointer write at field offset {i} (addr offset: {:#x}), gathered type: {cur_type:#x?}", i * POINTER_SIZE);
                        match table_types.get_mut(i) {
                            Some(common_type) => {
                                info!("Type exists, merging it into existing");
                                common_type.merge(&cur_type);
                            }
                            None => {
                                info!("Type does not exist, setting initial type");
                                table_types.push(cur_type);
                            }
                        }
                    } else {
                        // High entropy value. Not a pointer table
                        info!("[{i:#02x}] Got non-pointer write field offset {i} (addr offset: {:#x}), no pointer table...", i * POINTER_SIZE);
                        table_types.clear();
                        break 'outer;
                    }
                }
            }
        }
    }

    table_types
}

fn find_rx_tx_pairs(
    analysis_by_mmio_addr: &FxHashMap<MmioAddress, Vec<AccessAnalysisResult>>,
    mmio_addrs_by_buf_addr: &FxHashMap<RamAddress, FxHashSet<MmioAddress>>,
) -> FxHashMap<MmioAddress, RxTxPair> {
    /* Disambiguate between RX and TX pointer MMIO registers that re-use the same buffer
    - Challenge: The combination of buffers that
        1. get re-used for rx and tx by multiple MMIO registers
        2. don't get cleared prior to read (no initialization pattern)
    - Idea: Drop initialization requirement, if RX/TX buffer pair is detected
        - Fail case: Shared RX/TX buffer is used during TX to hold state (which is re-read  with the expectation that the data stays intact)
            - Not an issue, if: Buffer is written to (for TX), but not used as stateful (not re-read)
        - Apply if
            - Differing MMIO registers point to the same location
            - Re-writes of MMIO pointers multiple times (which we then assume to be per transaction)
            - Only a pair of MMIO pointers exists, not a larger set
        - TX buffer detection:
            - If any writes, the TX buffer has closest write to buffer BEFORE reconfiguration (before re-write of buffer pointer to MMIO register)
        - RX buffer detection
            - Closest Read-before-write AFTER reconfiguration (after re-write of buffer pointer to MMIO register)
     */

    /* For each buffer location, collect the corresponding
    MMIO addresses of descriptors referring to the address */
    let mut res: FxHashMap<MmioAddress, RxTxPair> = Default::default();
    let mut colliding_mmio_addrs: FxHashSet<MmioAddress> = Default::default();

    for (ram_addr, mmio_addrs) in mmio_addrs_by_buf_addr {
        // De-collide only instances of two buffers pointing at the same buffer
        // This is likely an rx / tx pair
        if mmio_addrs.len() == 2 {
            let mut it = mmio_addrs.iter();
            let mmio_addr_1 = it.next().unwrap();
            let mmio_addr_2: &u32 = it.next().unwrap();
            info!("Decolliding analysis pair for ram address {ram_addr:#x}: {mmio_addr_1:#x} vs {mmio_addr_2:#x}");

            // Only apply if we have multiple pointer writes to each MMIO register
            if analysis_by_mmio_addr[&mmio_addr_1].len() <= 1
                || analysis_by_mmio_addr[&mmio_addr_2].len() <= 1
            {
                info!("Did not get repeated MMIO pointer writes, not disambiguating");
                continue;
            }

            // Read immediately after configuring: likely an RX buffer
            let min_read_offset_1 = itertools::min(analysis_by_mmio_addr[&mmio_addr_1].iter().map(
                |analysis_result| {
                    match analysis_result.access_state {
                        AccessState::ReadBeforeWrite { read_time, .. } => {
                            read_time - analysis_result.mmio_access.trace_ind
                        }
                        _ => TraceId::MAX, // unreachable!() ?
                    }
                },
            ))
            .unwrap_or(TraceId::MAX);

            let min_read_offset_2 = itertools::min(analysis_by_mmio_addr[&mmio_addr_2].iter().map(
                |analysis_result| {
                    match analysis_result.access_state {
                        AccessState::ReadBeforeWrite { read_time, .. } => {
                            read_time - analysis_result.mmio_access.trace_ind
                        }
                        _ => TraceId::MAX, // unreachable!() ?
                    }
                },
            ))
            .unwrap_or(TraceId::MAX);
            let first_has_early_read = min_read_offset_1 < min_read_offset_2;
            let second_has_early_read = min_read_offset_2 < min_read_offset_1;

            // Non-trivial write just before configuring: likely a TX buffer
            let min_write_offset_1 =
                itertools::max(analysis_by_mmio_addr[&mmio_addr_1].iter().map(
                    |analysis_result: &AccessAnalysisResult| match &analysis_result.init_state {
                        InitializationState::Pattern {
                            latest_write_ind,
                            at_config: InitPattern { value, .. },
                            ..
                        } => {
                            // Skip any init patterns with trivial (typical initialization) values
                            if TRIVIAL_VALUES.contains(value) {
                                TraceId::MAX
                            } else {
                                match latest_write_ind {
                                    Some(latest_write_ind) => {
                                        analysis_result.mmio_access.trace_ind - latest_write_ind
                                    }
                                    None => TraceId::MAX,
                                }
                            }
                        }
                        InitializationState::Used {
                            latest_write_ind, ..
                        } => match latest_write_ind {
                            Some(latest_write_ind) => {
                                analysis_result.mmio_access.trace_ind - latest_write_ind
                            }
                            None => TraceId::MAX,
                        },
                        InitializationState::Uninitialized { .. } => TraceId::MAX,
                    },
                ))
                .unwrap_or(TraceId::MAX);

            let min_write_offset_2 =
                itertools::max(analysis_by_mmio_addr[&mmio_addr_2].iter().map(
                    |analysis_result: &AccessAnalysisResult| match &analysis_result.init_state {
                        InitializationState::Pattern {
                            latest_write_ind,
                            at_config: InitPattern { value, .. },
                            ..
                        } => {
                            // Skip any init patterns with trivial (typical initialization) values
                            if TRIVIAL_VALUES.contains(value) {
                                TraceId::MAX
                            } else {
                                match latest_write_ind {
                                    Some(latest_write_ind) => {
                                        analysis_result.mmio_access.trace_ind - latest_write_ind
                                    }
                                    None => TraceId::MAX,
                                }
                            }
                        }
                        InitializationState::Used {
                            latest_write_ind, ..
                        } => match latest_write_ind {
                            Some(latest_write_ind) => {
                                analysis_result.mmio_access.trace_ind - latest_write_ind
                            }
                            None => TraceId::MAX,
                        },
                        InitializationState::Uninitialized { .. } => TraceId::MAX,
                    },
                ))
                .unwrap_or(TraceId::MAX);

            let first_has_most_recent_write = min_write_offset_1 < min_write_offset_2;
            let second_has_most_recent_write = min_write_offset_2 < min_write_offset_1;
            // Both can only be the
            let has_no_writes =
                min_write_offset_1 == TraceId::MAX && min_write_offset_2 == TraceId::MAX;

            let rx_reg;
            let tx_reg;

            if (second_has_most_recent_write || has_no_writes) && first_has_early_read {
                rx_reg = *mmio_addr_1;
                tx_reg = *mmio_addr_2;
            } else if (first_has_most_recent_write || has_no_writes) && second_has_early_read {
                rx_reg = *mmio_addr_2;
                tx_reg = *mmio_addr_1;
            } else {
                info!("Did not find conclusive RX/TX decision, skipping (first_has_early_read: {first_has_early_read}, second_has_early_read: {second_has_early_read}, first_has_most_recent_write: {first_has_most_recent_write}, second_has_most_recent_write: {second_has_most_recent_write})");
                info!("min_write_offset_1: {min_write_offset_1:#x}, min_write_offset_2: {min_write_offset_2:#x}, min_read_offset_1: {min_read_offset_1:#x}, min_read_offset_2: {min_read_offset_2:#x}");
                continue;
            }

            info!("Decollided! Concluded rx address: {rx_reg:#x} and tx address: {tx_reg:#x}");

            if colliding_mmio_addrs.contains(&rx_reg) || colliding_mmio_addrs.contains(&tx_reg) {
                continue;
            }

            if res.contains_key(&rx_reg) || res.contains_key(&tx_reg) {
                warn!("Collision! Multiple ram buffers are refered to by the same MMIO registers (ram_addr: {ram_addr:#x}): {rx_reg:#x} and {tx_reg:#x}");
                colliding_mmio_addrs.insert(rx_reg);
                colliding_mmio_addrs.insert(tx_reg);
                res.remove(&rx_reg);
                res.remove(&tx_reg);
                continue;
            }

            res.insert(
                rx_reg,
                RxTxPair {
                    ram_addr: *ram_addr,
                    rx_reg,
                    tx_reg,
                },
            );

            res.insert(
                tx_reg,
                RxTxPair {
                    ram_addr: *ram_addr,
                    rx_reg,
                    tx_reg,
                },
            );
        }
    }

    res
}
