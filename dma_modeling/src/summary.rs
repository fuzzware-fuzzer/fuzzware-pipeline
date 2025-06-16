use fxhash::{FxHashMap, FxHashSet};
use std::cmp::{min, Ordering};

use itertools::Itertools;
use log::{info, log_enabled};
use serde::{Deserialize, Serialize};

use crate::common::{MmioAddress, RamAddress};
use crate::dma_analysis::{
    DmaBufMeta, FieldTypeGuess, PointerType, RxTxPair, SizeRange, REQUIRED_POINTER_ALIGNMENT,
};
use crate::dma_config::{DmaConfig, DmaDescriptorPointer};
use crate::dma_snippet::DmaAnalysisSnippet;

const NUM_MAX_DESCRIPTOR_POINTED_BUF_LOCATIONS: usize = 5;

/* DMA Descriptor detection constants */
const MAX_SRC_DST_FIELD_OFFSET: usize = 4;
const MAX_LINK_TO_SRC_DST_FIELD_OFFSET: usize = 7;
const MIN_DESCRIPTOR_FIELDS: usize = 4;
const MAX_DESCRIPTOR_FIELDS: usize = 8;

#[derive(Debug, Serialize, Deserialize)]
struct BufVoteEntry {
    num_votes: usize,
    buf: DmaBufMeta,
    size_votes: FxHashMap<RamAddress, FxHashMap<SizeRange, usize>>,
    conflicts: Vec<DmaBufMeta>,
}

impl BufVoteEntry {
    fn add_size_votes(&mut self, buf: &DmaBufMeta) {
        for (ram_addr, size_range) in &buf.dma_buf.known_sizes {
            let size_range_votes = self.size_votes.entry(*ram_addr).or_default();
            if let Some(count) = size_range_votes.get_mut(size_range) {
                *count += 1;
            } else {
                size_range_votes.insert(size_range.clone(), 1);
            }
        }
    }

    pub fn from_buf(buf: &DmaBufMeta) -> Self {
        let mut res = BufVoteEntry {
            num_votes: 1,
            buf: buf.clone(),
            conflicts: Default::default(),
            size_votes: Default::default(),
        };

        res.add_size_votes(buf);

        res
    }

    pub fn add_buf(&mut self, buf: &DmaBufMeta) -> bool {
        self.num_votes += 1;

        self.add_size_votes(buf);

        self.buf.is_compatible_with(buf)
    }
}

fn extract_buf_votes_from_fuzzware_snippets(
    snippets: &[DmaAnalysisSnippet],
    non_pointer_registers: &FxHashSet<MmioAddress>,
    tx_registers: &FxHashSet<MmioAddress>,
) -> FxHashMap<MmioAddress, BufVoteEntry> {
    let mut res: FxHashMap<MmioAddress, BufVoteEntry> = Default::default();

    for snip in snippets {
        for buf_snip in snip.detected_candidates.values() {
            if non_pointer_registers.contains(&buf_snip.mmio_address)
                || tx_registers.contains(&buf_snip.mmio_address)
            {
                continue;
            }

            if let Some(vote) = res.get_mut(&buf_snip.mmio_address) {
                if !vote.add_buf(&buf_snip) {
                    vote.conflicts.push(buf_snip.clone());
                }
            } else {
                res.insert(buf_snip.mmio_address, BufVoteEntry::from_buf(&buf_snip));
            }
        }
    }

    res
}

#[derive(Debug)]
pub struct RxTxPairVote {
    pair: RxTxPair,
    reverse_pair: RxTxPair,
    num_votes: usize,
    num_reverse_votes: usize,
}

fn extract_tx_registers(snippets: &[DmaAnalysisSnippet]) -> FxHashSet<MmioAddress> {
    let mut res: Vec<RxTxPairVote> = Default::default();

    for snip in snippets {
        for rx_tx_pair in &snip.rx_tx_pairs {
            if let Some(vote) = res.iter_mut().find(|v| v.pair == *rx_tx_pair) {
                vote.num_votes += 1;
            } else if let Some(vote) = res.iter_mut().find(|v| v.reverse_pair == *rx_tx_pair) {
                vote.num_reverse_votes += 1;
            } else {
                res.push(RxTxPairVote {
                    pair: rx_tx_pair.clone(),
                    reverse_pair: rx_tx_pair.create_reverse(),
                    num_votes: 1,
                    num_reverse_votes: 0,
                });
            }
        }
    }

    res.iter()
        .map(|rx_tx_pair_vote| {
            if rx_tx_pair_vote.num_votes > rx_tx_pair_vote.num_reverse_votes {
                rx_tx_pair_vote.pair.tx_reg
            } else {
                rx_tx_pair_vote.reverse_pair.tx_reg
            }
        })
        .collect()
}

fn extract_pointer_counterexamples(snippets: &[DmaAnalysisSnippet]) -> FxHashSet<MmioAddress> {
    let mut res: FxHashSet<MmioAddress> = Default::default();

    for snip in snippets {
        res.extend(snip.mmio_pointer_counterexamples.keys());
    }

    res
}

fn extract_misaligned_pointer_regs(snippets: &[DmaAnalysisSnippet]) -> FxHashSet<MmioAddress> {
    let mut res: FxHashSet<MmioAddress> = Default::default();

    for snip in snippets {
        res.extend(snip.misaligned_mmio_writes.keys());
    }

    res
}

fn extract_analyzed_mmio_addrs(snippets: &[DmaAnalysisSnippet]) -> FxHashSet<MmioAddress> {
    let mut res: FxHashSet<MmioAddress> = Default::default();

    for snip in snippets {
        res.extend(snip.analysis_by_mmio_addr.keys());
    }

    res
}

fn gather_common_types(
    snippets: &[DmaAnalysisSnippet],
    non_pointers: &FxHashSet<MmioAddress>,
    misaligned_pointers: &FxHashSet<MmioAddress>,
    tx_pointers: &FxHashSet<MmioAddress>,
) -> FxHashMap<MmioAddress, PointerType> {
    let mut res: FxHashMap<MmioAddress, PointerType> = Default::default();
    let mut already_skipped: FxHashSet<_> = Default::default();

    for snippet in snippets {
        for (mmio_addr, guessed_type) in &snippet.guessed_type_by_mmio_addr {
            if already_skipped.contains(mmio_addr) {
                continue;
            } else if non_pointers.contains(mmio_addr)
                || misaligned_pointers.contains(mmio_addr)
                || tx_pointers.contains(mmio_addr)
            {
                info!("Skipping type merging for invalid pointer: {mmio_addr:#x}");
                already_skipped.insert(mmio_addr);
                continue;
            }

            if let Some(existing_type) = res.get_mut(mmio_addr) {
                existing_type.merge(guessed_type);
            } else {
                res.insert(*mmio_addr, guessed_type.clone());
            }
        }
    }

    res
}

fn is_pointing_to_candidate(
    pointer: &PointerType,
    src_ptr_index: usize,
    dst_ptr_index: usize,
    link_ptr_index: usize,
) -> bool {
    info!("Checking candidate src: {src_ptr_index} dst: {dst_ptr_index} link: {link_ptr_index}");

    // For end-of-recursion-depth, just indicate true
    if pointer.to.len() == 0 {
        return true;
    }

    assert!([src_ptr_index, dst_ptr_index, link_ptr_index]
        .into_iter()
        .all(|ind| ind < pointer.to.len()));

    match &pointer.to[src_ptr_index] {
        FieldTypeGuess::Zero => {
            // Value is (always) NULL?
            info!("[-] src ptr is always NULL...");
            return false;
        }
        FieldTypeGuess::HighEntropy { .. } => {
            info!(
                "[-] src not a ptr at all (?!)... {:?}",
                pointer.to[src_ptr_index]
            );
            return false;
        }
        FieldTypeGuess::Pointer {
            pointer: src_ptr_candidate,
        } => {
            if !is_src_ptr_candidate(src_ptr_candidate) {
                info!("[-] not dst ptr...");
                return false;
            }
        }
    }

    if let FieldTypeGuess::Pointer {
        pointer: dst_ptr_candidate,
    } = &pointer.to[dst_ptr_index]
    {
        if !is_dst_ptr_candidate(dst_ptr_candidate) {
            info!("[-] not dst ptr...");
            return false;
        }
    } else {
        info!("[-] dst not a ptr at all (?!)...");
        info!("{:x?}", pointer.to[dst_ptr_index]);
        return false;
    }

    match &pointer.to[link_ptr_index] {
        FieldTypeGuess::Zero => true,
        FieldTypeGuess::HighEntropy { .. } => {
            info!("[-] link not a ptr at all (?!)...");
            false
        }
        FieldTypeGuess::Pointer {
            pointer: link_ptr_candidate,
        } => {
            if is_link_ptr_candidate(link_ptr_candidate) {
                // Recursively check the same conditions for the potential link
                if !is_pointing_to_candidate(
                    link_ptr_candidate,
                    src_ptr_index,
                    dst_ptr_index,
                    link_ptr_index,
                ) {
                    info!("[-] link not a ptr to candidate...");
                    false
                } else {
                    true
                }
            } else {
                false
            }
        }
    }
}

fn is_dst_ptr_candidate(pointer: &PointerType) -> bool {
    if pointer.includes_mmio {
        return false;
    }

    // Check that this is not clearly only used initialized
    // and at least at some points used uninitialized
    // Check for potential end-of-buffer pointer
    let is_potential_end_of_buf_ptr = pointer.potential_pre_buf_sizes.values().all(|v| *v != 0);

    (pointer.access_state_profile.has_read_before_write || is_potential_end_of_buf_ptr)
        && (!pointer.access_state_profile.has_write_before_read
            || pointer.init_state_profile.all_writes_trivial)
        && (pointer.init_state_profile.has_uninitialized || pointer.init_state_profile.has_pattern)
}

fn is_src_ptr_candidate(pointer: &PointerType) -> bool {
    pointer.includes_mmio && !(pointer.includes_misaligned_mmio && pointer.includes_null)
}

fn is_link_ptr_candidate(pointer: &PointerType) -> bool {
    !pointer.includes_mmio
}

#[derive(Default, Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DescriptorLayoutCandidate {
    pub src_ptr_index: usize,
    pub dst_ptr_index: usize,
    pub link_ptr_index: Option<usize>,
}

impl DescriptorLayoutCandidate {
    fn synthesize_from(pointer: &PointerType, start_offset: usize) -> Vec<Self> {
        let mut mmio_ptr_indices: Vec<usize> = Vec::new();
        let mut dst_ptr_indices: Vec<usize> = Vec::new();
        let mut link_ptr_indices: Vec<usize> = Vec::new();
        let fields = &pointer.to;

        for (i, field) in fields
            .iter()
            .skip(start_offset)
            .take(MAX_DESCRIPTOR_FIELDS)
            .enumerate()
        {
            let i = i + start_offset;
            if let FieldTypeGuess::Pointer { pointer } = field {
                if is_link_ptr_candidate(pointer) {
                    info!("[{i}] -> link?");
                    link_ptr_indices.push(i);
                }

                if is_dst_ptr_candidate(pointer) {
                    info!("[{i}] -> dst?");
                    dst_ptr_indices.push(i);
                }

                if is_src_ptr_candidate(pointer) {
                    info!("[{i}] -> src?");
                    mmio_ptr_indices.push(i);
                }
            }
        }

        let mut res: Vec<_> = Vec::new();
        for src_ptr_index in &mmio_ptr_indices {
            info!("Checking src {src_ptr_index}");
            for dst_ptr_index in &dst_ptr_indices {
                info!("Checking combination src_ptr_index: {src_ptr_index}, dst_ptr_index: {dst_ptr_index}");
                // Prune if src and dst are too far apart
                if src_ptr_index.abs_diff(*dst_ptr_index) > MAX_SRC_DST_FIELD_OFFSET {
                    info!("Src/Dst index difference too high...");
                    continue;
                }

                for link_ptr_index in &link_ptr_indices {
                    if link_ptr_index == dst_ptr_index {
                        continue;
                    }
                    info!("- Checking link ptr index: {link_ptr_index}");

                    // Prune if link ptr is too far away
                    if min(
                        link_ptr_index.abs_diff(*src_ptr_index),
                        link_ptr_index.abs_diff(*dst_ptr_index),
                    ) > MAX_LINK_TO_SRC_DST_FIELD_OFFSET
                    {
                        info!("Link pointer index difference too high...");
                        continue;
                    }
                    if is_pointing_to_candidate(
                        pointer,
                        *src_ptr_index,
                        *dst_ptr_index,
                        *link_ptr_index,
                    ) {
                        info!("Pointing to candidate!");
                        res.push(DescriptorLayoutCandidate {
                            src_ptr_index: *src_ptr_index,
                            dst_ptr_index: *dst_ptr_index,
                            link_ptr_index: Some(*link_ptr_index),
                        });
                    } else {
                        info!("Not pointing to candidate...");
                    }
                }
            }
        }

        // Test possible combinations
        for src_ptr_index in &mmio_ptr_indices {
            for dst_ptr_index in &dst_ptr_indices {
                // Prune if src and dst are too far apart
                if src_ptr_index.abs_diff(*dst_ptr_index) > MAX_SRC_DST_FIELD_OFFSET {
                    continue;
                }
                // also add option without any link pointer
                res.push(DescriptorLayoutCandidate {
                    src_ptr_index: *src_ptr_index,
                    dst_ptr_index: *dst_ptr_index,
                    link_ptr_index: None,
                });
            }
        }

        res
    }

    fn min_ind(&self) -> usize {
        let min_ind = min(self.dst_ptr_index, self.src_ptr_index);

        min_ind
    }

    fn min_diff(&self) -> usize {
        if self.dst_ptr_index > self.src_ptr_index {
            self.dst_ptr_index - self.src_ptr_index
        } else {
            self.src_ptr_index - self.dst_ptr_index
        }
    }

    fn ind_sum(&self) -> usize {
        self.src_ptr_index + self.dst_ptr_index
    }

    fn is_compatible_with(&self, other: &Self) -> bool {
        // either they are strictly the same, or src/dst pointer indices are swapped
        self == other
            || (self.dst_ptr_index == other.src_ptr_index
                && self.src_ptr_index == other.dst_ptr_index)
    }
}

fn determine_best_descriptor_candidate(
    candidates: &[DescriptorLayoutCandidate],
) -> DescriptorLayoutCandidate {
    assert!(!candidates.is_empty());

    if candidates.len() == 1 {
        return candidates[0].clone();
    }

    // 1. valid link >> NULL
    // 2. minimize distance between src/dest
    // 3. minimize overall distance / descriptor size
    // 4. minimize highest index
    let min_ind_candidate = candidates
        .iter()
        .min_by(|a, b| {
            let min_ind_a = a.min_ind();
            let min_ind_b = b.min_ind();

            if min_ind_a == min_ind_b {
                let min_diff_a = a.min_diff();
                let min_diff_b = b.min_diff();

                if min_diff_a == min_diff_b {
                    let has_valid_link_a = a.link_ptr_index.is_some();
                    let has_valid_link_b = b.link_ptr_index.is_some();

                    if has_valid_link_a == has_valid_link_b {
                        if has_valid_link_a {
                            a.link_ptr_index.cmp(&b.link_ptr_index)
                        } else {
                            a.ind_sum().cmp(&b.ind_sum())
                        }
                    } else {
                        if has_valid_link_a {
                            Ordering::Less
                        } else {
                            Ordering::Greater
                        }
                    }
                } else {
                    min_diff_a.cmp(&min_diff_b)
                }
            } else {
                min_ind_a.cmp(&min_ind_b)
            }
        })
        .unwrap();

    min_ind_candidate.clone()
}

fn synthesize_ram_based_linked_descriptors(
    analyzed_addrs: &FxHashMap<MmioAddress, PointerType>,
) -> FxHashMap<MmioAddress, DescriptorLayoutCandidate> {
    let mut candidate_per_mmio_addr: FxHashMap<MmioAddress, DescriptorLayoutCandidate> =
        Default::default();

    for (mmio_addr, pointer) in analyzed_addrs.iter() {
        info!("Looking at MMIO pointer: {mmio_addr:#x}");
        let candidates = DescriptorLayoutCandidate::synthesize_from(&pointer, 0);
        info!("Got RAM-based descriptor layout candidates: {candidates:#x?}");

        if !candidates.is_empty() {
            let top_candidate = determine_best_descriptor_candidate(&candidates);

            // Check that the best descriptor candidate does not point to too many different DMA buffers
            let buf_field = &pointer.to.get(top_candidate.dst_ptr_index);
            match buf_field {
                Some(FieldTypeGuess::Pointer { pointer }) => {
                    if pointer.known_values.len() > NUM_MAX_DESCRIPTOR_POINTED_BUF_LOCATIONS {
                        // Ensure that the DMA descriptor does not point to too many buffers
                        continue;
                    }
                }
                _ => {
                    // We should have a pointer here
                    debug_assert!(false);
                    continue;
                }
            }

            candidate_per_mmio_addr.insert(*mmio_addr, top_candidate);
        }
    }

    candidate_per_mmio_addr
}

fn synthesize_ram_based_descriptor_table(
    analyzed_addrs: &FxHashMap<MmioAddress, PointerType>,
) -> FxHashMap<MmioAddress, DescriptorLayoutCandidate> {
    let mut candidate_per_mmio_addr: FxHashMap<MmioAddress, DescriptorLayoutCandidate> =
        Default::default();

    for (mmio_addr, pointer) in analyzed_addrs.iter() {
        info!("Looking at MMIO pointer: {mmio_addr:#x}");

        // First, find the first populated entry of the potential DMA descriptor
        // For this purpose, skip fields containing Zero in chunks of the minimum descriptor field number
        let mut start_offset = 0;
        for chunk in pointer.to.chunks(MIN_DESCRIPTOR_FIELDS) {
            if chunk
                .iter()
                .all(|entry| matches!(entry, FieldTypeGuess::Zero))
            {
                start_offset += MIN_DESCRIPTOR_FIELDS;
            } else {
                break;
            }
        }
        info!("Skipping the first {start_offset} fields containing all Zero");

        // Next, see whether we have a descriptor at that location
        let candidates = DescriptorLayoutCandidate::synthesize_from(&pointer, start_offset);
        info!("Got RAM-based descriptor layout candidates: {candidates:#x?}");

        if !candidates.is_empty() {
            // We consider forward links for descriptors inside tables
            let top_candidate = determine_best_descriptor_candidate(&candidates);

            // Check that the best descriptor candidate does not point to too many different DMA buffers
            let buf_field = &pointer.to.get(top_candidate.dst_ptr_index);
            match buf_field {
                Some(FieldTypeGuess::Pointer { pointer }) => {
                    if pointer.known_values.len() > NUM_MAX_DESCRIPTOR_POINTED_BUF_LOCATIONS {
                        // Ensure that the DMA descriptor does not point to too many buffers
                        continue;
                    }
                }
                _ => {
                    // We should have a pointer here
                    debug_assert!(false);
                    continue;
                }
            }

            candidate_per_mmio_addr.insert(*mmio_addr, top_candidate);
        }
    }

    candidate_per_mmio_addr
}

fn synthesize_descriptor_pointer_table(
    analyzed_addrs: &FxHashMap<MmioAddress, PointerType>,
) -> FxHashMap<MmioAddress, FxHashMap<usize, DescriptorLayoutCandidate>> {
    let mut candidate_per_mmio_addr: FxHashMap<
        MmioAddress,
        FxHashMap<usize, DescriptorLayoutCandidate>,
    > = Default::default();
    // For each type info, check whether we have a pointer table
    // - NULL-terminated
    // - all (aligned) RAM pointers
    // - all point to descriptors
    // For each potential pointer table, check whether they point to descriptors

    for (mmio_addr, potential_table_ptr) in analyzed_addrs.iter() {
        // NULL-terminated pointer list?
        let mut num_pointer_table_fields = 0;
        for (i, field) in potential_table_ptr.to.iter().enumerate() {
            match field {
                FieldTypeGuess::Zero => {
                    num_pointer_table_fields = i;
                    break;
                }
                FieldTypeGuess::HighEntropy { .. } => {
                    // Arbitrary value: not a pointer table
                    num_pointer_table_fields = 0;
                    break;
                }
                FieldTypeGuess::Pointer { pointer } => {
                    if pointer.includes_mmio
                        || pointer
                            .known_values
                            .iter()
                            .any(|v| v & REQUIRED_POINTER_ALIGNMENT != 0)
                    {
                        num_pointer_table_fields = 0;
                        break;
                    } else {
                        num_pointer_table_fields = i;
                    }
                }
            }
        }

        if num_pointer_table_fields == 0 {
            info!("Not a descriptor pointer table: {mmio_addr:#x}");
            continue;
        } else {
            info!("Got a potential descriptor pointer table with {num_pointer_table_fields} pointers: {mmio_addr:#x}. Checking fields for being potential descriptors");
        }

        let mut descriptor_candidates: FxHashMap<_, _> = Default::default();

        for (i, potential_descr_ptr) in potential_table_ptr
            .to
            .iter()
            .take(num_pointer_table_fields)
            .enumerate()
        {
            if let FieldTypeGuess::Pointer { pointer } = potential_descr_ptr {
                let field_descr_candidates =
                    DescriptorLayoutCandidate::synthesize_from(&pointer, 0);
                if !field_descr_candidates.is_empty() {
                    let top_candidate =
                        determine_best_descriptor_candidate(&field_descr_candidates);
                    descriptor_candidates.insert(i, top_candidate);
                } else {
                    info!("Got no descriptor candidates for field {i} of potential table {mmio_addr:#x}, skipping entry");
                    break;
                }
            } else {
                unreachable!();
            }
        }

        // We have descriptor candidates for each field in the potential table
        if !descriptor_candidates.is_empty() {
            // We require somewhat the same descriptor layout for pointer tables (although src/dst may be swapped)
            // First, figure out the best candidate / most likely descriptor struct layout
            // Second, filter any other candidates that are incompatible with determined descriptor struct layout

            let flat_field_candidates: Vec<DescriptorLayoutCandidate> =
                descriptor_candidates.values().cloned().collect();
            let top_candidate =
                determine_best_descriptor_candidate(flat_field_candidates.as_slice());

            info!("Got {} candidates with top candidate {top_candidate:#x?}: {descriptor_candidates:x?}", descriptor_candidates.len());
            let mut offsets_incompatible_candidates: Vec<usize> = Default::default();
            for (field_offset, candidate) in &descriptor_candidates {
                if !top_candidate.is_compatible_with(candidate) {
                    offsets_incompatible_candidates.push(*field_offset);
                }
            }

            for field_offset in offsets_incompatible_candidates {
                info!("Removing incompatible candidate {field_offset}");
                descriptor_candidates.remove(&field_offset).unwrap();
            }
            candidate_per_mmio_addr.insert(*mmio_addr, descriptor_candidates);
        }
    }

    candidate_per_mmio_addr
}

pub fn summarize_snippets(snippets: &[DmaAnalysisSnippet]) -> Option<DmaConfig> {
    // Gather instances of invalid pointers
    let non_pointer_registers: FxHashSet<MmioAddress> = extract_pointer_counterexamples(snippets);
    info!(
        "Got {} non-pointer registers: {non_pointer_registers:#x?}",
        non_pointer_registers.len()
    );

    let misaligned_pointer_registers: FxHashSet<MmioAddress> =
        extract_misaligned_pointer_regs(snippets);
    info!(
        "Got {} misaligned pointer registers: {misaligned_pointer_registers:#x?}",
        misaligned_pointer_registers.len()
    );

    // 1. MMIO-based descriptor analysis (pointers to DMA buffers)
    let tx_registers = extract_tx_registers(snippets);
    info!("Got tx pointers: {tx_registers:#x?}");

    let votes_mmio: FxHashMap<MmioAddress, BufVoteEntry> =
        extract_buf_votes_from_fuzzware_snippets(snippets, &non_pointer_registers, &tx_registers);
    info!("Got votes: {votes_mmio:#x?}");

    // 2. RAM-based descriptor analysis
    let merged_types: FxHashMap<u32, PointerType> = gather_common_types(
        snippets,
        &non_pointer_registers,
        &misaligned_pointer_registers,
        &tx_registers,
    );
    if log_enabled!(log::Level::Info) {
        if !merged_types.is_empty() {
            info!("Got {} merged types:", merged_types.len());

            for (mmio_addr, merged_type) in &merged_types {
                info!("\n{mmio_addr:08x}: {:#x?}\n", merged_type);
            }
        }
    }

    // 2.1 Direct (linked) descriptors
    let ram_based_linked_descr_layouts: FxHashMap<u32, DescriptorLayoutCandidate> =
        synthesize_ram_based_linked_descriptors(&merged_types);
    info!("Got ram_based linked descriptor layouts: {ram_based_linked_descr_layouts:#x?}");

    let mut _tmp_descr_addrs = Default::default();
    let ram_based_linked_descr_config: FxHashMap<MmioAddress, DmaDescriptorPointer> =
        ram_based_linked_descr_layouts
            .iter()
            .map(|(mmio_addr, descr_layout)| {
                (
                    *mmio_addr,
                    DmaDescriptorPointer::from_dma_descriptor(
                        merged_types.get(mmio_addr).unwrap(),
                        descr_layout,
                        &mut _tmp_descr_addrs,
                    ),
                )
            })
            .collect();
    info!("Got ram_based linked descriptor configs: {ram_based_linked_descr_config:#x?}");

    // 2.2 Table of descriptors
    let ram_based_descr_layouts: FxHashMap<u32, DescriptorLayoutCandidate> =
        synthesize_ram_based_descriptor_table(&merged_types);
    info!("Got ram_based descriptor layouts: {ram_based_descr_layouts:#x?}");

    _tmp_descr_addrs.clear();
    let ram_based_descr_config: FxHashMap<MmioAddress, DmaDescriptorPointer> =
        ram_based_descr_layouts
            .iter()
            .map(|(mmio_addr, descr_layout)| {
                (
                    *mmio_addr,
                    DmaDescriptorPointer::from_dma_descriptor(
                        merged_types.get(mmio_addr).unwrap(),
                        descr_layout,
                        &mut _tmp_descr_addrs,
                    ),
                )
            })
            .collect();
    _tmp_descr_addrs.clear();
    info!("Got ram_based descriptor configs: {ram_based_descr_config:#x?}");

    // 2.3 Descriptor pointer tables
    let ram_based_descr_pointer_table_layouts = synthesize_descriptor_pointer_table(&merged_types);
    info!("Got ram_based pointer tables: {ram_based_descr_pointer_table_layouts:#x?}");
    for (mmio_addr, offset_to_ptr) in &ram_based_descr_pointer_table_layouts {
        let pointer = &merged_types[mmio_addr];

        info!("{mmio_addr:#x} -> {pointer:x?}");
        for (field_offset, descr_cand) in offset_to_ptr.iter() {
            let src_field = match &pointer.to[*field_offset] {
                FieldTypeGuess::Zero => unreachable!(),
                FieldTypeGuess::HighEntropy { .. } => unreachable!(),
                FieldTypeGuess::Pointer { pointer } => &pointer.to[descr_cand.src_ptr_index],
            };
            let dst_field = match &pointer.to[*field_offset] {
                FieldTypeGuess::Zero => unreachable!(),
                FieldTypeGuess::HighEntropy { .. } => unreachable!(),
                FieldTypeGuess::Pointer { pointer } => &pointer.to[descr_cand.dst_ptr_index],
            };

            info!("[{field_offset}] {descr_cand:?}\nsrc: {src_field:x?}\ndst: {dst_field:x?}");
        }
    }
    let ram_based_descr_pointer_table_config: FxHashMap<MmioAddress, DmaDescriptorPointer> =
        ram_based_descr_pointer_table_layouts
            .iter()
            .map(|(mmio_addr, layout_per_offset)| {
                (
                    *mmio_addr,
                    DmaDescriptorPointer::from_pointer_table(
                        merged_types.get(mmio_addr).unwrap(),
                        layout_per_offset,
                    ),
                )
            })
            .collect();

    // Print some summary info
    if log_enabled!(log::Level::Info) {
        let analyzed_addrs = extract_analyzed_mmio_addrs(snippets);
        let invalid_analyzed_addrs: Vec<&MmioAddress> = analyzed_addrs
            .intersection(&non_pointer_registers)
            .into_iter()
            .collect();

        if invalid_analyzed_addrs.is_empty() {
            info!("[+] No analyses of invalid MMIO addresses");
        } else {
            info!("Got analyzed MMIO addresses with a pointer counterexample!");

            for (i, mmio_addr) in invalid_analyzed_addrs.iter().enumerate() {
                info!("{i:02}: {mmio_addr:#x}");
            }
        }
    }

    // 3. Build config
    let mut dma_config: DmaConfig = Default::default();

    // 3.1 Add MMIO-based config
    for (mmio_addr, highest_vote) in votes_mmio
        .iter()
        .filter(|(mmio_addr, vote)| {
            vote.conflicts.is_empty()
                && !ram_based_descr_pointer_table_layouts.contains_key(&mmio_addr)
                && !ram_based_linked_descr_config.contains_key(&mmio_addr)
                && !ram_based_descr_config.contains_key(&mmio_addr)
        })
        .sorted_by(|(_, vote_1), (_, vote_2)| vote_2.num_votes.cmp(&vote_1.num_votes))
        // Currently, the implementation allows one RX buffer
        .take(1)
    {
        let highest_voted_sizes = highest_vote
            .size_votes
            .iter()
            .map(|(ram_addr, size_ranges)| {
                (
                    *ram_addr,
                    size_ranges
                        .iter()
                        .max_by_key(|(_, vote_count)| **vote_count)
                        .unwrap()
                        .0
                        .clone(),
                )
            })
            .collect();

        dma_config.add_descriptor(
            *mmio_addr,
            DmaDescriptorPointer::from_known_sizes(&highest_voted_sizes),
        );
        dma_config.add_known_buf_sizes(highest_voted_sizes);
    }

    // 3.2 Add RAM-based config
    // Pointers to DMA descriptor table
    for (mmio_addr, pointer) in ram_based_descr_config.into_iter() {
        if ram_based_linked_descr_config.contains_key(&mmio_addr) {
            continue;
        }
        info!("Adding RAM-based descriptor table for MMIO address {mmio_addr:#x}: {pointer:#x?}");
        dma_config.add_descriptor(mmio_addr, pointer);
    }

    // Pointers to linked DMA descriptors
    for (mmio_addr, pointer) in ram_based_linked_descr_config.into_iter() {
        info!("Adding RAM-based, linked descriptor for MMIO address {mmio_addr:#x}: {pointer:#x?}");
        dma_config.add_descriptor(mmio_addr, pointer);
    }

    // Descriptor pointer table
    for (mmio_addr, pointer) in ram_based_descr_pointer_table_config.into_iter() {
        info!("Adding RAM-based descriptor pointer table for MMIO address {mmio_addr:#x}: {pointer:#x?}");
        dma_config.add_descriptor(mmio_addr, pointer);
    }

    if dma_config.descriptor_heads.is_empty() {
        None
    } else {
        Some(dma_config)
    }
}
