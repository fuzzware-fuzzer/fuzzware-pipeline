use crate::common::{Address, TraceId};
use crate::hoedur::bintrace::{Access, AccessType, Trace, TraceEvent};
use std::ops::{Bound, RangeBounds};

// TODO: Endianness of target. Currently, little endian is assumed (see u32::from_le_bytes, to_le_bytes)

use fxhash::FxHashMap;

use endiannezz::Primitive;

#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub trace_ind: TraceId,
    pub value: u8,
}

pub enum TimeOrder {
    First,
    Last,
}

#[derive(Debug)]
pub struct MemoryHistory {
    // Stores memory locations and their history of values
    pub writes: FxHashMap<Address, Vec<HistoryEntry>>, // address -> Vec<(time, value)>
    pub reads: FxHashMap<Address, Vec<HistoryEntry>>,  // address -> Vec<(time, value)>
}

#[derive(Debug)]
pub struct MemoryView<'a, T: RangeBounds<TraceId>> {
    time: T,
    memory: &'a MemoryHistory,
}

impl<'a, T: RangeBounds<TraceId>> MemoryView<'a, T> {
    pub fn read_u8(&self, address: Address) -> Option<u8> {
        self.memory.writes.get(&address).and_then(|writes| {
            let last_write = writes.binary_search_by_key(&self.time_end(), |entry| entry.trace_ind);

            match last_write {
                Ok(index) => Some(writes[index].value),
                Err(index) if index == 0 => None,
                Err(index) => {
                    let entry = &writes[index - 1];
                    self.time.contains(&entry.trace_ind).then(|| entry.value)
                }
            }
        })
    }

    pub fn read<V: Primitive<Buf = [u8; N]>, const N: usize>(&self, address: Address) -> Option<V> {
        let mut data = [0u8; N];

        for i in 0..N {
            data[i] = self.read_u8(address + i as Address)?;
        }

        Some(V::from_le_bytes(data))
    }

    #[allow(unused)]
    fn time_start(&self) -> TraceId {
        match self.time.start_bound() {
            Bound::Included(start) => *start,
            Bound::Excluded(start) => start.saturating_add(1),
            Bound::Unbounded => TraceId::MIN,
        }
    }

    fn time_end(&self) -> TraceId {
        match self.time.end_bound() {
            Bound::Included(end) => *end,
            Bound::Excluded(end) => end.saturating_sub(1),
            Bound::Unbounded => TraceId::MAX,
        }
    }

    pub fn is_initialized(&self, address: Address) -> bool {
        self.memory
            .writes
            .get(&address)
            .and_then(|writes| {
                let last_write =
                    writes.binary_search_by_key(&self.time_end(), |entry| entry.trace_ind);

                Some(match last_write {
                    Ok(_) => true,
                    Err(index) if index == 0 => false,
                    Err(index) => self.time.contains(&writes[index - 1].trace_ind),
                })
            })
            .unwrap_or(false)
    }
}

pub fn read<T: Primitive<Buf = [u8; N]>, const N: usize>(memory: &[u8], address: usize) -> T {
    let data: [u8; N] = memory[address..address + N].try_into().unwrap();

    T::from_le_bytes(data)
}

impl Default for MemoryHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryHistory {
    pub fn new() -> Self {
        MemoryHistory {
            writes: Default::default(),
            reads: Default::default(),
        }
    }

    pub fn add_access(&mut self, event_ind: TraceId, access: &Access) {
        let bytes: [u8; 4] = access.value.to_le_bytes();
        let hm: &mut FxHashMap<u32, Vec<HistoryEntry>> = match access.access_type {
            AccessType::Write => &mut self.writes,
            AccessType::Read => &mut self.reads,
        };
        for (i, val) in bytes.iter().take(access.size as usize).enumerate() {
            hm.entry(access.address + i as u32)
                .or_default()
                .push(HistoryEntry {
                    trace_ind: event_ind,
                    value: *val,
                });
        }
    }

    pub fn add_trace_entry(&mut self, event_ind: TraceId, event: &TraceEvent) {
        match event {
            // Update the memory history for the given address
            TraceEvent::Access(access) => {
                self.add_access(event_ind, access);
            }
        }
    }

    // Parses a trace file and populates memory history
    pub fn load_trace(&mut self, trace: &Trace) {
        for (event_ind, event) in trace.events.iter().enumerate() {
            self.add_trace_entry(event_ind as TraceId, event);
        }
    }

    pub fn mem_view_at<T: RangeBounds<TraceId>>(&self, time: T) -> MemoryView<T> {
        MemoryView {
            time,
            memory: &self,
        }
    }

    pub fn get_history_entry<T: RangeBounds<TraceId>>(
        &self,
        address: Address,
        time: &T,
        access_type: AccessType,
        time_order: TimeOrder,
    ) -> Option<&HistoryEntry> {
        // find last read within time range
        match access_type {
            AccessType::Read => &self.reads,
            AccessType::Write => &self.writes,
        }
        .get(&address)
        .and_then(|history| match time_order {
            TimeOrder::First => history.iter().find(|entry| time.contains(&entry.trace_ind)),
            TimeOrder::Last => history
                .iter()
                .rev()
                .find(|entry| time.contains(&entry.trace_ind)),
        })
    }

    fn next_access<T: RangeBounds<TraceId>>(
        &self,
        address: u32,
        time: &T,
        access_type: AccessType,
    ) -> Option<&HistoryEntry> {
        self.get_history_entry(address, time, access_type, TimeOrder::First)
    }

    fn last_access<T: RangeBounds<TraceId>>(
        &self,
        address: u32,
        time: &T,
        access_type: AccessType,
    ) -> Option<&HistoryEntry> {
        self.get_history_entry(address, time, access_type, TimeOrder::Last)
    }

    pub fn next_read<T: RangeBounds<TraceId>>(
        &self,
        address: u32,
        time: &T,
    ) -> Option<&HistoryEntry> {
        self.next_access(address, time, AccessType::Read)
    }

    pub fn next_write<T: RangeBounds<TraceId>>(
        &self,
        address: u32,
        time: &T,
    ) -> Option<&HistoryEntry> {
        self.next_access(address, time, AccessType::Write)
    }

    pub fn last_read<T: RangeBounds<TraceId>>(
        &self,
        address: u32,
        time: &T,
    ) -> Option<&HistoryEntry> {
        self.last_access(address, time, AccessType::Read)
    }

    pub fn last_write<T: RangeBounds<TraceId>>(
        &self,
        address: u32,
        time: &T,
    ) -> Option<&HistoryEntry> {
        self.last_access(address, time, AccessType::Write)
    }

    // Returns the value of a memory location at a specific timestamp
    pub fn latest_write_at(&self, address: u32, timestamp: TraceId) -> Option<&HistoryEntry> {
        self.writes
            .get(&address)
            .and_then(|history| self.get_latest_event_until(history, timestamp))
    }

    // Returns the value of a memory location at a specific timestamp
    pub fn latest_read_at(&self, address: u32, timestamp: TraceId) -> Option<&HistoryEntry> {
        self.reads
            .get(&address)
            .and_then(|history| self.get_latest_event_until(history, timestamp))
    }

    // Returns the value of a memory location at a specific timestamp
    pub fn get_u8_at(&self, address: u32, timestamp: TraceId) -> Option<u8> {
        self.writes.get(&address).and_then(|history| {
            self.get_latest_event_until(history, timestamp)
                .map(|x| x.value)
        })
    }

    pub fn get_u8_between(&self, address: u32, start_ind: TraceId, end_ind: TraceId) -> Option<u8> {
        self.writes.get(&address).and_then(|history| {
            self.get_next_event_between(history, start_ind, end_ind)
                .map(|x| x.value)
        })
    }

    // Returns the time and value of a memory location if written after specific timestamp
    pub fn get_u8_after(&self, address: u32, timestamp: TraceId) -> Option<u8> {
        self.writes.get(&address).and_then(|history| {
            self.get_next_event_after(history, timestamp)
                .map(|x| x.value)
        })
    }

    // Returns the value of a memory location at a specific timestamp
    pub fn get_u32_at(&self, address: u32, timestamp: TraceId) -> Option<u32> {
        let bytes = [
            self.get_u8_at(address, timestamp)?,
            self.get_u8_at(address + 1, timestamp)?,
            self.get_u8_at(address + 2, timestamp)?,
            self.get_u8_at(address + 3, timestamp)?,
        ];
        Some(u32::from_le_bytes(bytes))
    }

    // Returns the time and value of a memory location if written after specific timestamp
    pub fn get_32_after(&self, address: u32, timestamp: TraceId) -> Option<u32> {
        let bytes = [
            self.get_u8_after(address, timestamp)?,
            self.get_u8_after(address + 1, timestamp)?,
            self.get_u8_after(address + 2, timestamp)?,
            self.get_u8_after(address + 3, timestamp)?,
        ];
        Some(u32::from_le_bytes(bytes))
    }

    // Returns the latest value of a memory location
    pub fn get_latest_u8(&self, address: u32) -> Option<u8> {
        self.writes
            .get(&address)
            .and_then(|history| history.last().map(|entry| entry.value))
    }

    // Returns the latest value of a memory location
    pub fn get_latest_u32(&self, address: u32) -> Option<u32> {
        let bytes = [
            self.get_latest_u8(address)?,
            self.get_latest_u8(address + 1)?,
            self.get_latest_u8(address + 2)?,
            self.get_latest_u8(address + 3)?,
        ];
        Some(u32::from_le_bytes(bytes))
    }

    fn get_events_between<'a>(
        &self,
        history: &'a [HistoryEntry],
        start_ind: &'a TraceId,
        end_ind: &'a TraceId,
    ) -> impl Iterator<Item = &'a HistoryEntry> {
        history
            .iter()
            .skip_while(|entry: &&HistoryEntry| entry.trace_ind < *start_ind)
            .take_while(|entry: &&HistoryEntry| entry.trace_ind < *end_ind)
    }

    fn get_next_event_after<'a>(
        &self,
        history: &'a [HistoryEntry],
        timestamp: TraceId,
    ) -> Option<&'a HistoryEntry> {
        history.iter().find(|entry| entry.trace_ind > timestamp)
    }

    fn get_next_event_between<'a>(
        &self,
        history: &'a [HistoryEntry],
        start_ind: TraceId,
        end_ind: TraceId,
    ) -> Option<&'a HistoryEntry> {
        history
            .iter()
            .take_while(|entry| entry.trace_ind < end_ind)
            .find(|entry| entry.trace_ind > start_ind)
    }

    pub fn get_writes_between(
        &self,
        address: u32,
        start_ind: TraceId,
        end_ind: TraceId,
    ) -> Option<Vec<HistoryEntry>> {
        self.writes.get(&address).map(|x| {
            self.get_events_between(x, &start_ind, &end_ind)
                .cloned()
                .collect()
        })
    }

    pub fn get_latest_writes_between(
        &self,
        address: u32,
        address_end: u32,
        start_ind: TraceId,
        end_ind: TraceId,
    ) -> Vec<HistoryEntry> {
        (address..address_end)
            .map_while(|address| self.get_latest_write_between(address, start_ind, end_ind))
            .collect()
    }

    pub fn get_between(
        &self,
        address: u32,
        address_end: u32,
        start_ind: TraceId,
        end_ind: TraceId,
    ) -> Vec<u8> {
        self.get_latest_writes_between(address, address_end, start_ind, end_ind)
            .iter()
            .map(|entry| entry.value)
            .collect()
    }

    pub fn get_latest_write_between(
        &self,
        address: u32,
        start_ind: TraceId,
        end_ind: TraceId,
    ) -> Option<HistoryEntry> {
        self.writes.get(&address).and_then(|x| {
            self.get_events_between(x, &start_ind, &end_ind)
                .last()
                .cloned()
        })
    }

    fn get_latest_event_until<'a>(
        &self,
        history: &'a [HistoryEntry],
        timestamp: TraceId,
    ) -> Option<&'a HistoryEntry> {
        history
            .iter()
            .rev()
            .find(|entry| entry.trace_ind <= timestamp)
    }

    pub fn get_read_after(&self, address: u32, timestamp: TraceId) -> Option<&HistoryEntry> {
        self.reads
            .get(&address)
            .and_then(|history| self.get_next_event_after(history, timestamp))
    }

    pub fn get_write_after(&self, address: u32, timestamp: TraceId) -> Option<&HistoryEntry> {
        self.writes
            .get(&address)
            .and_then(|history| self.get_next_event_after(history, timestamp))
    }

    // Prints the entire memory history for debugging
    pub fn print_memory(&self) {
        for (address, history) in &self.writes {
            println!("Address: {:x}", address);
            for entry in history {
                println!("  trace_ind: {}, Value: {:x}", entry.trace_ind, entry.value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hoedur::bintrace::{Access, AccessTarget};

    #[test]
    fn test_mem_view() {
        const ADDR: u32 = 0x12341338;
        const TESTVAL: u32 = 0x12341338;
        const OVERRIDE_VAL: u32 = 0x5678;

        // Simulate a simple trace loading
        let trace = Trace {
            events: vec![
                TraceEvent::Access(Access {
                    target: AccessTarget::Ram,
                    access_type: AccessType::Write,
                    size: 4,
                    pc: 0,
                    address: ADDR,
                    value: TESTVAL,
                }),
                TraceEvent::Access(Access {
                    target: AccessTarget::Ram,
                    access_type: AccessType::Write,
                    size: 4,
                    pc: 0,
                    address: ADDR + 2,
                    value: OVERRIDE_VAL,
                }),
            ],
        };

        let mut mem_view = MemoryHistory::new();
        mem_view.load_trace(&trace);

        // Test values at different timestamps
        assert_eq!(mem_view.get_u8_at(ADDR + 2, 0), Some((TESTVAL >> 16) as u8));
        assert_eq!(
            mem_view.get_u8_at(ADDR + 5, 1),
            Some((OVERRIDE_VAL >> 24) as u8)
        );
        assert_eq!(
            mem_view.get_u8_at(ADDR + 4, 1),
            Some((OVERRIDE_VAL >> 16) as u8)
        );

        assert_eq!(mem_view.get_u32_at(ADDR, 0), Some(TESTVAL));
        assert_eq!(
            mem_view.get_u32_at(ADDR, 1),
            Some((TESTVAL as u16) as u32 | (((OVERRIDE_VAL as u16) as u32) << 16))
        );

        // Test non-written memory
        assert_eq!(mem_view.get_u8_at(ADDR + 6, 1), None);
        assert_eq!(mem_view.get_u32_at(ADDR + 3, 1), None);

        // Test latest value
        assert_eq!(mem_view.get_latest_u32(ADDR + 2), Some(OVERRIDE_VAL));
        assert_eq!(mem_view.get_latest_u32(ADDR + 3), None);
        assert_eq!(
            mem_view.get_latest_u32(ADDR + 2),
            mem_view.get_u32_at(ADDR + 2, 1)
        );

        // Test between-based API
        assert_eq!(
            mem_view.get_between(ADDR + 4, ADDR + 6, 0, 1),
            Vec::<u8>::new()
        ); // First access does not modify 4-6
        assert_eq!(
            mem_view.get_between(ADDR + 1, ADDR + 3, 1, 2),
            Vec::<u8>::new()
        ); // Second access does not modify 0-1

        assert_eq!(
            mem_view.get_between(ADDR + 0, ADDR + 4, 0, 1),
            TESTVAL.to_le_bytes()
        ); // First access modifies 0-3
        assert_eq!(
            mem_view.get_between(ADDR + 2, ADDR + 6, 1, 2),
            OVERRIDE_VAL.to_le_bytes()
        ); // Second access modifies 2-5

        assert_eq!(
            mem_view.get_between(ADDR + 2, ADDR + 4, 0, 1),
            ((TESTVAL >> 16) as u16).to_le_bytes()
        ); // First access modifies 0-3
        assert_eq!(
            mem_view.get_between(ADDR + 4, ADDR + 6, 1, 2),
            ((OVERRIDE_VAL >> 16) as u16).to_le_bytes()
        ); // Second access modifies 2-5

        let mut full_final_val = Vec::with_capacity(6);
        full_final_val.extend_from_slice(&(TESTVAL as u16).to_le_bytes());
        full_final_val.extend_from_slice(&(OVERRIDE_VAL).to_le_bytes());
        assert_eq!(
            mem_view.get_between(ADDR + 0, ADDR + 6, 0, 2),
            full_final_val
        );
    }
}
