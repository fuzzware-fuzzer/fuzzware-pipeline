use itertools::Itertools;
use memmap::{Mmap, MmapOptions};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::PathBuf;

use regex::Regex;

use crate::hoedur::bintrace::{Access, AccessTarget, AccessType, Trace, TraceEvent};

type TraceEntry = (u32, Access);

fn parse_ram_trace_mmap_it(f: File) -> impl Iterator<Item = TraceEntry> {
    TraceIterator::new(f)
}

#[allow(unused)]
fn parse_ram_trace(path: &PathBuf) -> Vec<TraceEntry> {
    let input = File::open(path).unwrap();
    parse_ram_trace_mmap_it(input).collect()
}

#[allow(unused)]
fn parse_ram_trace_slow(path: &PathBuf) -> Vec<TraceEntry> {
    parse_ram_trace_regex(path)
}

#[allow(unused)]
fn parse_mmio_trace(path: &PathBuf) -> Vec<Access> {
    let input = File::open(path).unwrap();
    parse_mmio_trace_it(input)
        .map(|p: (u32, Access)| p.1)
        .collect()
}

pub fn parse_mmio_trace_it(f: File) -> impl Iterator<Item = TraceEntry> {
    let buffered: io::BufReader<File> = io::BufReader::new(f);

    // 1ffe: 12b6 1617 r 4 64 4 0x40094008:7c6e5ef4 7c7c7c7c
    // event_id, pc, lr, mode, orig_access_size, access_fuzz_ind, num_consumed_fuzz_bytes, address, val_text
    buffered.lines().map(|line| {
        let line: String = line.unwrap();
        let ind_end_event_id = line.find(": ").unwrap();
        let event_id_str = &line[0..ind_end_event_id];
        let line = &line[ind_end_event_id + 2..];
        let ind_end_address = line.find(":").unwrap();
        let mut it = line[..ind_end_address].split(" ");
        let pc_str = it.next().unwrap();
        let _ = it.next(); // Skip lr
        let mode_str = it.next().unwrap();
        let orig_access_size_str = it.next().unwrap();
        let _ = it.next(); // Skip access_fuzz_ind
        let _ = it.next(); // Skip num_consumed_fuzz_bytes
        let address_str = it.next().unwrap();
        let value_str = &line[ind_end_address + 1..];

        let event_id = u32::from_str_radix(event_id_str, 16).unwrap();
        let pc = u32::from_str_radix(pc_str, 16).unwrap();
        // let lr = u32::from_str_radix(lr_str, 16).unwrap();
        let mode = mode_str.bytes().next().unwrap();
        let size = orig_access_size_str.parse::<u8>().unwrap();
        let address = u32::from_str_radix(&address_str[2..], 16).unwrap();
        let value: u32 = u32::from_str_radix(value_str.split(" ").last().unwrap(), 16).unwrap();

        (
            event_id,
            Access {
                target: AccessTarget::Mmio,
                pc,
                access_type: if mode == b'r' {
                    AccessType::Read
                } else {
                    AccessType::Write
                },
                size,
                address,
                value,
            },
        )
    })
}

/*
    Reference trace parsing based on regex (as done in the fuzzware python code)
*/
fn parse_ram_trace_regex(path: &PathBuf) -> Vec<TraceEntry> {
    // Open the file
    let input = File::open(path).unwrap();
    let buffered: io::BufReader<File> = io::BufReader::new(input);
    let contents: String = io::read_to_string(buffered).unwrap();

    // Define your regular expression
    let re: Regex =
        Regex::new(r"([0-9a-f]+): ([0-9a-f]+) ([0-9a-f]+) ([rw]) ([\d]) 0x([0-9a-f]+)\:(.*)")
            .unwrap();

    let res: Vec<TraceEntry> =
        // for caps in re.captures_iter(&contents) {
        re.captures_iter(&contents).map(| caps | {
            // skip full line match
            let mut it = caps.iter().skip(1);

            // event_id, pc, lr, mode, size, address, val_text
            let event_id = u32::from_str_radix(it.next().unwrap().unwrap().as_str(), 16).unwrap();
            let pc = u32::from_str_radix(it.next().unwrap().unwrap().as_str(), 16).unwrap();
            #[allow(unused)]
            let lr = u32::from_str_radix(it.next().unwrap().unwrap().as_str(), 16).unwrap();
            let mode = it.next().unwrap().unwrap().as_str().as_bytes()[0];
            let size = it.next().unwrap().unwrap().as_str().parse::<u8>().unwrap();
            let address_str = it.next().unwrap().unwrap().as_str();
            let address = u32::from_str_radix(address_str, 16).unwrap();
            let value_str = it.next().unwrap().unwrap().as_str();
            let value: u32 = u32::from_str_radix(value_str.split(" ").last().unwrap(), 16).unwrap();

            (
            event_id,
            Access {
                target: AccessTarget::Ram,
                pc,
                access_type: if mode == b'r' {
                    AccessType::Read
                } else {
                    AccessType::Write
                },
                size,
                address,
                value,
            },
        )
        }).collect();

    res
}

/* ugly, but rather highly optimized, manual parsing of RAM trace lines.
Optimizations:
- mmap file (need unsafe here :-/)
- parse bytes, not string
- only read each byte once
- manually iterate over bytes and hex-decode on the fly
- use lookup-based hex decoding without hex validity checking
*/
const HEX_DECODE_TABLE: [u8; 256] = {
    let mut array = [0; 256];

    array['0' as usize] = 0;
    array['1' as usize] = 1;
    array['2' as usize] = 2;
    array['3' as usize] = 3;
    array['4' as usize] = 4;
    array['5' as usize] = 5;
    array['6' as usize] = 6;
    array['7' as usize] = 7;
    array['8' as usize] = 8;
    array['9' as usize] = 9;

    array['a' as usize] = 10;
    array['b' as usize] = 11;
    array['c' as usize] = 12;
    array['d' as usize] = 13;
    array['e' as usize] = 14;
    array['f' as usize] = 15;

    array['A' as usize] = 10;
    array['B' as usize] = 11;
    array['C' as usize] = 12;
    array['D' as usize] = 13;
    array['E' as usize] = 14;
    array['F' as usize] = 15;

    array
};

struct TraceIterator {
    map: Mmap,
    parse_ind: usize,
}

impl TraceIterator {
    pub fn new(file: File) -> TraceIterator {
        TraceIterator {
            map: unsafe { MmapOptions::new().map(&file) }.unwrap(),
            parse_ind: 0,
        }
    }
}

impl Iterator for TraceIterator {
    type Item = (u32, Access);
    fn next(&mut self) -> Option<Self::Item> {
        if self.parse_ind >= self.map.len() {
            return None;
        }

        let mut cursor = self.parse_ind;

        // Parse event ID
        let mut event_id: u32 = 0;
        let mut c;
        loop {
            c = self.map[cursor];
            if c == b':' {
                break;
            }
            event_id <<= 4;
            event_id += HEX_DECODE_TABLE[c as usize] as u32;
            cursor += 1;
        }
        cursor += 2;

        // Parse pc
        let mut pc: u32 = 0;
        loop {
            c = self.map[cursor];
            if c == b' ' {
                break;
            }
            pc <<= 4;
            pc |= HEX_DECODE_TABLE[c as usize] as u32;
            cursor += 1;
        }
        cursor += 1;

        // Skip LR (which we don't use)
        loop {
            c = self.map[cursor];
            if c == b' ' {
                break;
            }
            cursor += 1;
        }

        // Parse mode + size
        let mode = self.map[cursor + 1];
        let size = self.map[cursor + 3] - b'0';
        cursor += 5;

        // Parse address
        // Skip 0x
        cursor += 2;
        // Find colon after address
        let mut address: u32 = 0;
        loop {
            c = self.map[cursor];
            if c == b':' {
                break;
            }
            address <<= 4;
            address |= HEX_DECODE_TABLE[c as usize] as u32;
            cursor += 1;
        }
        cursor += 1;

        // Parse value (use only the last value)
        let value_text = &self.map[cursor..];

        // We parse each value and discard it in case it is not the last
        let value: u32 = value_text
            .iter()
            .take_while(|x| **x != b'\n')
            .fold(0, |acc, elem| {
                cursor += 1;
                if *elem == b' ' {
                    // Reset to 0 to skip prev-to-last values
                    0
                } else {
                    (acc << 4) | HEX_DECODE_TABLE[*elem as usize] as u32
                }
            });
        debug_assert!(cursor == self.map.len() || self.map[cursor] == b'\n');
        cursor += 1;

        self.parse_ind = cursor;

        let res = (
            event_id,
            Access {
                target: AccessTarget::Ram,
                pc,
                access_type: if mode == b'r' {
                    AccessType::Read
                } else {
                    debug_assert!(mode == b'w', "{}", mode);
                    AccessType::Write
                },
                size,
                address,
                value,
            },
        );

        Some(res)
    }
}

impl Trace {
    pub fn from_fuzzware_traces(ram_trace_path: &PathBuf, mmio_trace_path: &PathBuf) -> Self {
        let it_ram = parse_ram_trace_mmap_it(File::open(ram_trace_path).unwrap());
        let it_mmio = parse_mmio_trace_it(File::open(mmio_trace_path).unwrap());

        Trace {
            events: it_ram
                .merge_by(it_mmio, |(trace_id_a, _), (trace_id_b, _)| {
                    trace_id_a <= trace_id_b
                })
                .map(|p: (u32, Access)| TraceEvent::Access(p.1))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzware_ram_trace_parsing() {
        let trace_dir = std::env::current_exe()
            .unwrap()
            .ancestors()
            .skip(4)
            .next()
            .unwrap()
            .join("testdata/fuzzware_traces");
        let ram_trace_path = trace_dir.join("ram_trace.txt");
        println!("{:?}", ram_trace_path);
        let ram_trace = parse_ram_trace(&ram_trace_path);
        let ram_trace_reference = parse_ram_trace_slow(&ram_trace_path);

        assert_eq!(ram_trace, ram_trace_reference);

        let mmio_trace_path = trace_dir.join("mmio_trace.txt");
        let mmio_trace = parse_mmio_trace(&mmio_trace_path);

        assert!(!mmio_trace.is_empty());
    }
}
