#!/usr/bin/env python3
import argparse
import os

from fuzzware_harness.tracing.serialization import parse_bbl_trace, parse_mem_trace, parse_mmio_trace
from fuzzware_harness.util import load_config_deep, parse_symbols, parse_address_value, bytes2int

MAX_IN_STRUCT_DWORDS = 10
MMIO_SEARCH_RANGE = 6
BUF_SIZE_BIAS = 3
LOG = 0

POINTER = "pointer"
MMIO_REG = "mmio_reg"
NULL = "zero"
UNDEFINED = "no_idea"
LLI_PTR = "linked_list_pointer"
NON_ZERO = "non_zero"

FORWARD = 'forward'
BACKWARD = 'backward'
FPOINTERS = 'forward_pointers'
BPOINTERS = 'backwar_pointers'

MMIO_DMA = 'mmio'
SG_DMA = 'sg'



RESULT_SG = "scatter_gather"
RESULT_ACCESS = "access_pc"
RESULT_CONFIG = "config_pc"
RESULT_DESCRIPTOR = "descriptor"
RESULT_EVENT = "event_id"
RESULT_SIZE_MAX = "max_size"
RESULT_SIZE_MIN = "size"
RESULT_MMIO = "mmio_address"


##########################
###### HELPER FUNCs ######
##########################
def setup_parser(parser):
    """ 
    Setup the argparser 
    """
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--log', type=int, default=0)
    parser.add_argument('-c', '--config', default="config.yml")
    parser.add_argument('--mmio-trace', default="mmio_trace.txt")
    parser.add_argument('--bb-trace', default="bb_trace.txt")
    parser.add_argument('--ram-trace', default="ram_trace.txt")
    parser.add_argument('--start-symbol', default='main')

    return

def set_log(log):
    global LOG
    LOG = log

def debug_log(output: str):
    if LOG == 2:
        print(f"[+] {output}") 

def log(output: str):
    """ 
    Some small log mechanism 
    """
    if LOG > 0:
        print(f"[+] {output}")

    return

def order_symbols(name_to_addr):
    """ order symbols by address """
    entries = []
    for name, addr in name_to_addr.items():
        entries.append((addr, name))
    return sorted(entries, key=lambda x: x[0])

    return

def nearest_symbol(ordered_symbols, target_address):
    # log("Looking up addr: 0x{:08x}".format(target_address))
    prev_addr, prev_name = None, None
    for sym_addr, name in ordered_symbols:
        # log(f"Looking at sym_addr, name = {sym_addr} {name}")
        if prev_addr is None and prev_addr is None:
            prev_addr, prev_name = sym_addr, name
        else:
            if sym_addr > target_address:
                return prev_addr, prev_name
            else:
                prev_addr, prev_name = sym_addr, name
    return None, None

MAX_OFF = 0x1000
def nearest_symbol_string(ordered_symbols, target_address):
    addr, name = nearest_symbol(ordered_symbols, target_address)
    if addr is None or name is None:
        return "unknown"

    off = target_address - addr
    if off > MAX_OFF:
        return "unknown"
    return "{}{}".format(name, "+0x{:x}".format(off) if off else "")

def extract_irq_addresses(config):
    """ 
    Extract irq address ranges from config 
    """
    ranges = []
    for name, reg_config in config.get('memory_map').items():
        if "irq_ret" in name.lower():
            ranges.append((reg_config['base_addr'], reg_config['base_addr']+reg_config['size']))
    return ranges

def extract_ram_addresses(config):
    """ 
    Extract ram address ranges from config 
    """
    ranges = []
    for name, reg_config in config.get('memory_map').items():
        #TODO exclude text segment????
        if "text" in name.lower():
            continue
        # exclude null page for now
        if reg_config['base_addr'] == 0:
            continue
        if "mmio" in name.lower() or "irq_ret" in name.lower() or "nvic" in name.lower():
            continue
        ranges.append((reg_config['base_addr'], reg_config['base_addr']+reg_config['size']))
    return ranges

def extract_mmio_addresses(config):
    """ 
    Extract mmio address ranges from config 
    """
    ranges = []
    for name, reg_config in config.get('memory_map').items():
        if "mmio" in name.lower():
            ranges.append((reg_config['base_addr'], reg_config['base_addr']+reg_config['size']))
    return ranges

def in_range(ranges, addr):
    """
    Check if an address is within a given set of ranges
    """
    for start, end in ranges:
        if start <= addr <= end:
            return True
    
    return False

def get_starting_event_id(start_addr, bbl_trace_path):
    """
    Return event_id of the starting event
    """
    for event_id, pc, cnt in parse_bbl_trace(bbl_trace_path):
        if pc >= start_addr:
            return event_id
    return None

def follow_write_path(predecessors, addr):
    """
    Follow write path, used for nice output
    """
    res = [addr]
    while addr in predecessors:
        addr = predecessors[addr]
        if addr in res:
            break
        res.append(addr)
    return res[::-1]

def log_write_path(chain, ordered_symbols, pcs_per_read_addr, pcs_per_write_addr):
    """
    log write path. used for nice output
    """
    debug_log("Path: ")
    tokens = []
    for addr in chain:
        read_pcs = pcs_per_read_addr.get(addr)
        write_pcs = pcs_per_write_addr.get(addr)
        read_pc_descr = nearest_symbol_string(ordered_symbols, list(read_pcs)[0]) if read_pcs else "-"
        write_pc_descr = nearest_symbol_string(ordered_symbols, list(write_pcs)[0]) if write_pcs else "-"
        addr_descr = nearest_symbol_string(ordered_symbols, addr)
        token = f"0x{addr:x} ({addr_descr:}, written to at: {write_pc_descr:}, read from: {read_pc_descr})"
        tokens.append(token)

    debug_log("\n -> ".join(tokens)+"\n")

def get_val(val_text: str) -> int:
    # Safe way to access the val field
    end_ind_first_val = val_text.find(' ')
    if end_ind_first_val != -1:
        val_text = val_text[:end_ind_first_val]
    return int(val_text, 16)