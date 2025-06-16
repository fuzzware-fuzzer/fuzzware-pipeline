#!/usr/bin/env python3
from fuzzware_pipeline.dma.dma_util import *
from fuzzware_pipeline.dma.dma_sg import get_potential_descriptors

import itertools

cached_fw_init_addrs = (0, 0, set())

def get_mmio_written_ram_addresses(ram_addr_ranges: list, mmio_trace_path: str):
    """
    Extract all ram addresses that were written to ram and return them as well as some
    meta information.

    Args:
        ram_addr_ranges (list): list of tuples representing the configured ram addr ranges
        mmio_trace_path (str): Path to the mmio trace file
        
    Returns:
        set(): ram addresses written to mmio
        dict(int: set()): pcs of the mmio read accesses
        dict(int: set()): pcs of the mmio write accesses
        dict(int: set()): ram addresses written to mmio and all addresses they were written to
        dict(int: int): ram addresses written to mmio and the event id of the write
        dict(int: int): ram addresses written to mmio and the pc of the write 
    """
    ram_addrs = set()
    pcs_per_mmio_access = {"r": {}, "w": {}}
    mmio_addrs_per_mmio_written_ram_addr = {}
    eventid_per_mmio_written_ram_addrs = {}
    all_event_ids_per_mmio_written_ram_addrs = {}
    pcs_per_mmio_written_ram_addr = {}
    
    for event_id, pc, lr, mode, orig_access_size, access_fuzz_ind, num_consumed_fuzz_bytes, mmio_addr, val_text in parse_mmio_trace(mmio_trace_path):
        vals = [int(x, 0x10) for x in val_text.split(" ")]

        for v in vals:
            if in_range(ram_addr_ranges, v):
                ram_addrs.add(v)
                if mode == "w":
                    if v not in eventid_per_mmio_written_ram_addrs: 
                        eventid_per_mmio_written_ram_addrs[v] = event_id
                        pcs_per_mmio_written_ram_addr[v] = pc
                    if v not in all_event_ids_per_mmio_written_ram_addrs:
                        all_event_ids_per_mmio_written_ram_addrs[v] = dict() #{mmio_addr: event_id}
                    if mmio_addr not in all_event_ids_per_mmio_written_ram_addrs[v]:
                        all_event_ids_per_mmio_written_ram_addrs[v][mmio_addr] = list()
                    all_event_ids_per_mmio_written_ram_addrs[v][mmio_addr].append(event_id)

                    if v not in mmio_addrs_per_mmio_written_ram_addr:
                        mmio_addrs_per_mmio_written_ram_addr[v] = set()

                    mmio_addrs_per_mmio_written_ram_addr[v].add(mmio_addr)
                if v not in pcs_per_mmio_access[mode]:
                    pcs_per_mmio_access[mode][mmio_addr] = set()

                pcs_per_mmio_access[mode][mmio_addr].add(pc)

    return ram_addrs, pcs_per_mmio_access['r'], pcs_per_mmio_access['w'], mmio_addrs_per_mmio_written_ram_addr, eventid_per_mmio_written_ram_addrs, pcs_per_mmio_written_ram_addr, all_event_ids_per_mmio_written_ram_addrs





#                      Proxy config metric
#      config phase of candidate    |  look for reads to candidate        
#   t------------------------------[+]------------------------------> t
def dumb_find_uninit_reads(mem_trace, ram_addr_ranges, eventid_per_mmio_written_ram_addrs, event_id_per_dma_ptr, pcs_per_mmio_written_ram_addr, pcs_per_dma_ptr):
    """Alternative approach of finding uninitialized reads, by only looking at the non-config
    part of the firmware. This allows for the detection of pre-initialized dma bufs.
    Args:
        ram_trace (string): filename of the ram_trace
        ram_addr_ranges (list): start and end addresses of the ram ranges
        eventid_per_mmio_written_ram_addrs (dict): ram addresses written to mmio and the event id of the write
        event_id_per_dma_ptr (dict): ram addresses written to a potential dma descriptor and the event id of the write
        pcs_per_mmio_written_ram_addr: ram addresses written to mmio and the pc of the write
        pcs_per_dma_ptr: ram addresses written to a potential dma descriptor and the event id of the write
        dma_config (dict): existing dma config, we might want to build on
    Return:
        Dict(int: list()): {addr: [size, mmio/s-g config pc, access pc]}
    """

    uninitialized_bufs = {MMIO_DMA: dict(), SG_DMA: dict()}
    mmio_ptr_per_event_id = dict([(e, a) for a,e in eventid_per_mmio_written_ram_addrs.items()])
    ram_ptr_per_event_id = dict([(e, a) for a,e in event_id_per_dma_ptr.items()])

    # TODO get config pairs also from descriptors
    # Config pairs are all ram pointers written to MMIO or a (potential) descriptor struct
    config_pairs = dict(sorted([(addr, event_id) for addr, event_id in eventid_per_mmio_written_ram_addrs.items()], key=lambda item: item[1]))
    all_config_pairs = dict(sorted([(event_id, addr) for event_id, addr in {**mmio_ptr_per_event_id, **ram_ptr_per_event_id}.items()], key=lambda item: item[0]))
    # look for potential dma bufs using the different config boundaries 
    for event_id, ram_addr in all_config_pairs.items():
        if event_id in ram_ptr_per_event_id:
            debug_log("======================== DESCRIPTOR")
            debug_log(hex(ram_addr))
            uninitialized_bufs[SG_DMA].update(test_config_pairs(mem_trace, event_id, ram_addr_ranges, dict(), pcs_per_dma_ptr))
        if event_id in mmio_ptr_per_event_id:
            log("======================== MMIO")
            log(f"eventid for val {ram_addr:#x} is {event_id:#x}")
            uninitialized_bufs[MMIO_DMA].update(test_config_pairs(mem_trace, event_id, ram_addr_ranges, pcs_per_mmio_written_ram_addr, dict()))
    debug_log(uninitialized_bufs)
    return uninitialized_bufs

def get_candidates_per_eventid(ram_trace: list, config_boundary: int):
    """
    Args:
        ram_trace (list):
        config_boundary (int):

    Returns:
    """
    #print(hex(config_boundary))
    global cached_fw_init_addrs

    seen_addrs = set()
    read_before_write = set()
    read_before_write_event_id = dict()
    fw_initialized_addrs = set()
    written_mem = set()
    read_only_sizes = {}
    read_pcs = {}
    read_vals = dict()
    written_vals = dict()
    pattern_and_addrs = dict()
    current_pattern = -1
    pattern_min_length = 5
    cached_event_id = 0
    cached_index = 0
    if cached_fw_init_addrs[0]:
        cached_event_id, cached_index, fw_initialized_addrs = cached_fw_init_addrs

    cur_index = cached_index
    to_cache = 0
    for event_id, pc, lr, mode, size, address, val_text in itertools.islice(ram_trace, None):
        cur_index += 1
        if event_id >= config_boundary and not to_cache:
            to_cache = cur_index
        if event_id < cached_event_id:
            continue
        # Before the assumed configuration: Look for pre-initialized values
        if event_id < config_boundary:
            seen_addrs.add(address)
            if mode == "w":
                written_val = get_val(val_text)
                written_vals[address] = written_val
                current_pattern = entropy_check(address, size, written_val, current_pattern, pattern_and_addrs, pattern_min_length, fw_initialized_addrs)
                #debug_log(f"address: {address:#x} pattern: {current_pattern:#x}, current length: {len(pattern_and_addrs):#x}, {fw_initialized_addrs}")
                #debug_log("=========================")
            else:
                assert(mode == "r")
                if address in fw_initialized_addrs:
                    #debug_log(f"---Removing {address:#x} (REASON Re-Read)")
                    #fw_initialized_addrs.remove(address)
                    pass
            continue
        
        # Add/remove remaining set
        if pattern_and_addrs:
            for start_addrs, field in pattern_and_addrs.items():
                pattern_addr_and_sizes = field[1]
                if len(pattern_addr_and_sizes) >= pattern_min_length:
                    # we add those to the pre initialized 
                    #debug_log(f"+++Adding stored addresses belonging to bucket {start_addrs:#x}")
                    fw_initialized_addrs.update(flatten_mem_start_size_dict(pattern_addr_and_sizes))
                else: 
                    #debug_log(f"---removing stored addresses belonging to bucket {start_addrs:#x}")
                    fw_initialized_addrs.difference_update(flatten_mem_start_size_dict(pattern_addr_and_sizes))
                pattern_addr_and_sizes = list()
            pattern_and_addrs = dict()

        # After the assumed configuration: Look for read-before-write values

        if mode  == "w":
            # val text check to detect flushed buffers
            if address in read_before_write and val_text != '0':
                continue

            written_mem.add(address)
        else:
            debug_log(f"Got address {address:#x}")
            assert(mode == "r")
            if address in written_mem:
                debug_log(f"Not Adding {address:#x}")
                continue

            if address in read_before_write:
                continue

            debug_log(f"Adding {address:#x}")
            read_before_write.add(address)
            read_only_sizes[address] = size
            read_pcs[address] = pc
            read_before_write_event_id[address] = event_id
            read_vals[address] = get_val(val_text)

            # If a value is truly uninitialized and has never been touched before, we add it to the set as well
            if address not in seen_addrs and val_text == "0":
            #if val_text == "0":
                #debug_log(f"!!! {address:#x}")
                fw_initialized_addrs.add(address)

    # Cache the fw_initialized addresses to speed up further execution
    cached_fw_init_addrs = (config_boundary, to_cache, fw_initialized_addrs)
    return read_before_write, read_before_write_event_id, fw_initialized_addrs, written_vals, written_mem, read_vals, read_pcs, read_only_sizes

def test_config_pairs(ram_trace: list, config_boundary: int, ram_addr_ranges: list, pcs_per_mmio_written_ram_addr: dict, pcs_per_dma_ptr: dict):
    """ 
    Given a config boundary, first look for buffers or memory areas that are pre-initialized with the same value. 
    This aims to solve the problem, that dma-buffers may either implicitly initialized with a stack poisoning value other than zero,
    or explicitly initialized by the firmware (e.g, memset). 
    Next, we look for all ram addresses that are read-before-write AFTER the config boundary.
    Then we extract all of those read-before-writes that were to a location, which is either uninitialized, or which has been pre-initialized as
    described above.
    These are dma buffer candidates
    
    Args:
        ram_trace (list): parsed ram trace
        config_boundary (int): event_id where the end of the config is assumed to be
        ram_addr_ranges (List): List of tuples which contain the ram addr ranges
        pcs_per_mmio_written_ram_addr (dict):
        pcs_per_dma_ptr (dict)
    Return:
        dict(int: list()): Dict containing start address and size of dma buf candidates
    """
    log(f"Config boundary is {config_boundary:#x}")
    read_before_write, read_before_write_event_id, fw_initialized_addrs, written_vals, written_mem, read_vals, read_pcs, read_only_sizes = get_candidates_per_eventid(ram_trace, config_boundary)
    debug_log("READ B4 WRITE MEM")
    debug_log([hex(x) for  x in read_before_write])
    #debug_log([hex(x) for  x in fw_initialized_addrs])

    # Remove all addresses from read-before-write that are not pre-initialized, but contain user/firmware data
    read_but_not_fw = sorted(read_before_write - fw_initialized_addrs)
    prelim_read_before_write = sorted(read_before_write & fw_initialized_addrs)
    debug_log("READ B4 WRITE MEM")
    debug_log([hex(x) for  x in prelim_read_before_write])
    
    # Now we need to remove false positives, which can arise when we already detected dma
    # Step 1: Remove if last written != read b4 write val
    read_before_write = set()
    for reads in prelim_read_before_write:
        if reads in written_vals and written_vals[reads] != read_vals[reads]:
            continue    
        read_before_write.add(reads)

    # Step 2 TODO look at the existing config

    debug_log("READ B4 WRITE MEM")
    debug_log([hex(x) for  x in read_before_write])


    if not read_before_write:
        return {}
    
    # calculate sizes of the dma buffer candidates
    uninitialized_bufs = {}
    cur_start_addr = -1
    cur_address = -1
    cur_size = 0
    # TODO sometimes there is an off by one/two in the size
    for address in read_before_write:
        if cur_start_addr == -1:
            cur_start_addr = address
            cur_address = address
            continue

        else:
            if cur_address + read_only_sizes[cur_address] == address:
                cur_address = address
                if cur_size == 0:
                    cur_size += read_only_sizes[cur_address]

                else:
                    cur_size += read_only_sizes[cur_address]
            else:
                cur_size += read_only_sizes[cur_address]

            if cur_address != address:
                config_pc = -1
                scatter_gather = 0
                if cur_start_addr in pcs_per_mmio_written_ram_addr:
                    config_pc = pcs_per_mmio_written_ram_addr[cur_start_addr]
                elif cur_start_addr in pcs_per_dma_ptr:
                    config_pc = pcs_per_dma_ptr[cur_start_addr]['pc']
                    scatter_gather = pcs_per_dma_ptr[cur_start_addr]['base']
                # this means we've reached the next buffer, add to dict and reset
                # TODO skip if config_pc = -1?
                uninitialized_bufs[cur_start_addr] = {RESULT_SIZE_MIN: cur_size, 
                                                    RESULT_CONFIG: config_pc, 
                                                    RESULT_ACCESS: read_pcs[cur_start_addr], 
                                                    RESULT_SG: 0, 
                                                    RESULT_EVENT: read_before_write_event_id[cur_start_addr]}
                cur_start_addr = address
                cur_address = address
                cur_size = 0
    
    # add the last buf of the loop to the dict
    # TODO skip if config_pc = -1?
    # This seems awfully redundant
    config_pc = -1
    scatter_gather = 0
    if cur_start_addr in pcs_per_mmio_written_ram_addr:
        config_pc = pcs_per_mmio_written_ram_addr[cur_start_addr]
    elif cur_start_addr in pcs_per_dma_ptr:
        config_pc = pcs_per_dma_ptr[cur_start_addr]['pc']
        scatter_gather = pcs_per_dma_ptr[cur_start_addr]['base']
    uninitialized_bufs[cur_start_addr] = {RESULT_SIZE_MIN: read_only_sizes[cur_start_addr] if not cur_size else cur_size, 
                                            RESULT_CONFIG: config_pc, 
                                            RESULT_ACCESS: read_pcs[cur_start_addr], 
                                            RESULT_SG: scatter_gather,
                                            RESULT_EVENT: read_before_write_event_id[cur_start_addr]
                                            }


    # Some false psoitive detection (TOOD maybe remove in the false positive elim)
    # First, removing all non referenced buffers
    # Store all removed buffers in the read_but_not_fw


    for start_addr, field in uninitialized_bufs.items():
        if start_addr not in pcs_per_mmio_written_ram_addr:
            if start_addr not in pcs_per_dma_ptr:
                read_but_not_fw.extend([x for x in range(start_addr, start_addr + field[RESULT_SIZE_MIN])])    

    debug_log(uninitialized_bufs)
    pruned = dict()
    debug_log("###Pruning####")
    debug_log(pcs_per_dma_ptr)
    found_smth = False
    for start_addr, field in uninitialized_bufs.items():
        debug_log(f"### Pruning {start_addr:#x}")  

        for descriptor_ram_addr in sorted(pcs_per_dma_ptr, reverse = True):
            debug_log(f"\t{descriptor_ram_addr:#x}")
            if descriptor_ram_addr >= start_addr and descriptor_ram_addr < start_addr + field[RESULT_SIZE_MIN]:
                debug_log(f"got match2 for {start_addr:#x} and {descriptor_ram_addr:#x}  and size {field[RESULT_SIZE_MIN]:#x}")
                scatter_gather = pcs_per_dma_ptr[descriptor_ram_addr]['base']
                pruned[descriptor_ram_addr] = {RESULT_SIZE_MIN: start_addr + field[RESULT_SIZE_MIN] - descriptor_ram_addr,
                                               RESULT_CONFIG: field[RESULT_CONFIG], 
                                                RESULT_ACCESS: field[RESULT_ACCESS], 
                                                RESULT_SG: scatter_gather,
                                                RESULT_EVENT: field[RESULT_EVENT]}
                break

        for mmio_ram_addr in sorted(pcs_per_mmio_written_ram_addr, reverse = True) :
            if mmio_ram_addr >= start_addr and mmio_ram_addr < start_addr + field[RESULT_SIZE_MIN]:
                debug_log(f"got match1 for {start_addr:#x} and {mmio_ram_addr:#x} and size {field[RESULT_SIZE_MIN]:#x}")
                field.update({RESULT_SIZE_MIN: start_addr + field[RESULT_SIZE_MIN] - mmio_ram_addr})
                pruned[mmio_ram_addr] = {RESULT_SIZE_MIN: start_addr + field[RESULT_SIZE_MIN] - mmio_ram_addr,
                                            RESULT_CONFIG: field[RESULT_CONFIG], 
                                                RESULT_ACCESS: field[RESULT_ACCESS], 
                                                RESULT_SG: 0,
                                                RESULT_EVENT: field[RESULT_EVENT]}


        
        if start_addr in pcs_per_mmio_written_ram_addr:
            pruned[start_addr] = field
            continue

        """
        if start_addr in pcs_per_dma_ptr:
            pruned[start_addr] = field
            scatter_gather = pcs_per_dma_ptr[start_addr]['base']
            pruned[start_addr][RESULT_SG] = scatter_gather
        """


    #pruned = dict([(start_addr, field) for start_addr, field in uninitialized_bufs.items() if start_addr in pcs_per_mmio_written_ram_addr or start_addr in pcs_per_dma_ptr])
    debug_log(pruned)
    # Max Size detection
    # There are two approaches: Either uses the firmware initialized buffersize or look at the next, non sequential access to memory after the dma buffer candidate
    for start_addr, field in pruned.items():
        debug_log("=======================================")
        cur_size = field[RESULT_SIZE_MIN]
        debug_log(f"{start_addr:#x}: got min size {cur_size:#x}")  
        debug_log("Approach 1")     
        succ = -1
        max_size_1 = cur_size
        for i in sorted(fw_initialized_addrs):
            if i < start_addr:
                continue
            if i == start_addr:
                succ = start_addr
                continue
            
            if succ + 4 >= i:
                max_size_1 += i - succ
                succ = i
        debug_log(f"=== for {start_addr:#x} max size is {max_size_1:#x}")

        debug_log(f"Approach 2")
        max_size_2 = 0
        for i in sorted(written_mem | set(read_but_not_fw)):
            if i < start_addr + field[RESULT_SIZE_MIN]:
                continue
            
            max_size_2 = i - start_addr
            break
        debug_log(f"=== for {start_addr:#x} max size is {max_size_2:#x}")

        # Pick the lower max size of the candidates
        max_size = min([max_size_1, max_size_2])
        debug_log(f"=== Choosing {max_size:#x}")
        field[RESULT_SIZE_MAX] = max_size

    return pruned

def flatten_mem_start_size_dict(addr_and_size) -> set:
    #print("================================")
    #print(addr_and_size)
    #print( set(hex(x) for start, l in addr_and_size for x in [start + i for i in range(0, l)]))
    return set(x for start, l in addr_and_size for x in [start + i for i in range(0, l)])

def entropy_check(address: int, size: int, written_val: int, current_pattern: int, pattern_and_addrs: dict, pattern_min_length: int, fw_initialized_addrs: set):
    """
    To check whether a buffer was implicitly initialized via a (Stack) poisoning val or explicitly by the firmware, we check for the entropy of its contents.
    If the firmware writes the same pattern to a consecutive region of memory (i.e., at least <pattern_min_length>), we assume this region to be preinitialized and
    add its members to the f(irm)w(are)_initialized_address. If the consecutive region is too short or the patterns differ we remove those addresses from
    the fw_intitialized_addrs set.

    Args:
        address (int): current ram address to inspect
        size(int): size of the write
        val_text (str): contents of the write
        current_pattern (int): current pattern, i.e., what was written to the previous address
        pattern_addrs_and_sizes (dict): list of tuples of address and sizes, that were written with the current pattern, at a given start addr
        pattern_min_length (int): Minimal required length after which a consecutively initlaized region is stored
        fw_initialized_addrs (set): Set of firmware initlized adresses
    Returns:
        int: The value written to the current addres, i.e., the pattern to compare with during the next write
        list((int, int)): The updated list of tuples with the addresses and sizes that were written with the current pattern 
        set(int): Updated set of firmware initialized addresses
    Returns:
    """
    #pattern addr and sizes = {start_addr: (current_pattern, [(addr1, size1), (addr2, size2), ..., (addrn, sizen)])}

    if written_val == 0:
        #debug_log(f"0+++Adding stored addresses belonging to bucket {address:#x}")
        fw_initialized_addrs.update(flatten_mem_start_size_dict([(address, size)]))
        #debug_log(fw_initialized_addrs)
        return 0

    # already have the start address 
    if address in pattern_and_addrs:
        pattern_addrs_and_sizes = pattern_and_addrs[address][1]
        if len(pattern_addrs_and_sizes) >= pattern_min_length:
            #debug_log(f"1+++Adding stored addresses belonging to bucket {address:#x}")
            fw_initialized_addrs.update(flatten_mem_start_size_dict(pattern_addrs_and_sizes))
        else: 
            #debug_log(f"---removing stored addresses belonging to bucket {address:#x}")
            fw_initialized_addrs.difference_update(flatten_mem_start_size_dict(pattern_addrs_and_sizes))
        current_pattern = written_val
        pattern_and_addrs[address] = (current_pattern, [(address, size)])
        return current_pattern

    # TODO initial case?   
    to_pop = list()
    for start_addr, val in pattern_and_addrs.items():
        pattern = val[0]
        pattern_addrs_and_sizes = val[1]
        # check if we are a consecutive write
        # and our address is consecutive to the last one
        if (address == (pattern_addrs_and_sizes[-1][0] + pattern_addrs_and_sizes[-1][1]) or address + size == pattern_addrs_and_sizes[0][0]):
            #debug_log(f"current address {address:#x} matches to bucket with start address {start_addr:#x}")
            # and the pattern is the same 
            if written_val == pattern:
                # append the current address
                if address > start_addr:
                    pattern_addrs_and_sizes.append((address, size))
                else: 
                    pattern_addrs_and_sizes.insert(0, (address, size))
                return current_pattern

            #debug_log(f"---> Pattern differs")
            # pattern differs????
    
            # If the pattern is different or the address is not consecutive:
            # Add or remove the previous consecutive region to/from the set, depending on its length
            if len(pattern_addrs_and_sizes) >= pattern_min_length:
                #debug_log(f"2+++Adding stored addresses belonging to bucket {start_addr:#x}")
                fw_initialized_addrs.update(flatten_mem_start_size_dict(pattern_addrs_and_sizes))
            else: 
                #debug_log(f"---removing stored addresses belonging to bucket {start_addr:#x}")
                fw_initialized_addrs.difference_update(flatten_mem_start_size_dict(pattern_addrs_and_sizes))
            to_pop.append(start_addr)
            break
    
        if address in [x[0] for x in pattern_addrs_and_sizes]:
            if len(pattern_addrs_and_sizes) >= pattern_min_length:
                #debug_log(f"3+++Adding stored addresses belonging to bucket {start_addr:#x}")
                fw_initialized_addrs.update(flatten_mem_start_size_dict(pattern_addrs_and_sizes))
            else: 
                #debug_log(f"---removing stored addresses belonging to bucket {start_addr:#x}")
                fw_initialized_addrs.difference_update(flatten_mem_start_size_dict(pattern_addrs_and_sizes))
            to_pop.append(start_addr)
            break

    if to_pop:
        pattern_and_addrs.pop(start_addr)

    # Add new entry
    current_pattern = written_val
    pattern_and_addrs[address] = (current_pattern, [(address, size)])
    #debug_log(f"Creating new bucket with start_addr {address:#x}")
    return current_pattern


def dumb_false_positive_elim(mmio_written_ram_addrs, uninit_bufs_and_sizes: dict, potential_dma_ptrs, ram_addr_ranges):
    """
    We eliminate false positives, by removing all dma buf candidates which are not referenced in
    mmio or in a dma struct. Also some edge cases are taken care of.
   
    Args:
        mmio_written_ram_addr (list): List of ram addresses written to mmio
        uninit_bufs_and_sizes (dict): Dict containing start address and size of buffers that were 
                                      read w/o being written first and are therefore dma cands
        potential_dma_ptrs TODO
        ram_addr_ranges (list): Valid ram address ranges
    Return:
        result (dict): dma buffer candidates after f/p elim
        sg_result (dict): potential scatter gather dma buffer
    """

    # MMIO CHECK
    #debug_log("False positive elim")
    mmio_dma_bufs = uninit_bufs_and_sizes[MMIO_DMA]
    tmp_bufs = {}
    for uninit_buf, field in mmio_dma_bufs.items():
        if not in_range(ram_addr_ranges, uninit_buf):
            #debug_log(f"reason 1 removing {uninit_buf:#x}")
            continue

        tmp_bufs[uninit_buf] = field

        # remove from result if buffer == start of a segment (e.g., ram)
        for ram_range in ram_addr_ranges:
            if uninit_buf == ram_range[0]:
                #debug_log(f"reason 3 removing {uninit_buf:#x}")
                tmp_bufs.pop(uninit_buf)
                continue

        if uninit_buf in mmio_written_ram_addrs:
            # there is a potential case, where two dma buffers are next to each other, and the 
            # analysis will categorize them as one buffer! 
            # example: nxp-lpc1837_pdma_memory
            for mmio_written_ram_addr in mmio_written_ram_addrs:
                if uninit_buf < mmio_written_ram_addr < uninit_buf + field[RESULT_SIZE_MIN]:
                    if mmio_written_ram_addr in list(mmio_dma_bufs.keys()):
                        break
                    # TODO
                    tmp_bufs[mmio_written_ram_addr] = {RESULT_SIZE_MIN: uninit_buf + mmio_dma_bufs[uninit_buf] - mmio_written_ram_addr}

                break

    uninit_bufs_and_sizes[MMIO_DMA] = tmp_bufs

    #Scatter/Gather check
    #TODO first sg check? or not
    sg_result = {}
    return uninit_bufs_and_sizes, sg_result

def annotate_results(uninit_bufs_and_sizes: dict, mmio_addrs_per_mmio_written_ram_addr: dict, all_event_ids_per_mmio_written_ram_addrs: dict, back_descriptor: dict, lli_descriptors: dict):
    """
    Given some (potential) dma buffers, extract their corresponding mmio address.
    """
    for dma_type, entry in uninit_bufs_and_sizes.items():
        for start_addr, field in entry.items():
            # If multiple mmio registers point to the buffer only use the one closes before the detected access
            if dma_type == MMIO_DMA:
                # NORMAL
                if start_addr in mmio_addrs_per_mmio_written_ram_addr:
                    if len(all_event_ids_per_mmio_written_ram_addrs[start_addr]) > 1:
                        debug_log("Multiple MMIO case")
                        access_event_id = field[RESULT_EVENT]
                        min_delta = 0xffffffff
                        val = -1
                        for mmio_addr, event_ids in all_event_ids_per_mmio_written_ram_addrs[start_addr].items():
                            debug_log(f"looking @ candidate {mmio_addr:#x}")
                            for event_id in event_ids:
                                delta = access_event_id - event_id
                                if delta > 0 and  delta < min_delta:
                                    min_delta = delta
                                    val = mmio_addr
                        debug_log(f"choosing {val:#x}")
                        field[RESULT_MMIO] = val
                        continue
                    # else there should only be one address, which we can just pop
                    field[RESULT_MMIO] = mmio_addrs_per_mmio_written_ram_addr[start_addr].pop()
                else:
                    field[RESULT_MMIO] = -1

            if dma_type == SG_DMA:
                # SCATTER GATHER
                debug_log("Found scatter gather")
                sg_descr = field[RESULT_SG]
                if back_descriptor:
                    sg_descr = back_descriptor[field[RESULT_SG]]

                field[RESULT_MMIO] = next(iter(all_event_ids_per_mmio_written_ram_addrs[sg_descr]))
                field[RESULT_DESCRIPTOR] = lli_descriptors[sg_descr]

    if not uninit_bufs_and_sizes[MMIO_DMA]:
        uninit_bufs_and_sizes.pop(MMIO_DMA)
    if not uninit_bufs_and_sizes[SG_DMA]:
        uninit_bufs_and_sizes.pop(SG_DMA)
    return uninit_bufs_and_sizes

def get_ram_traces(ram_trace: str):
    ram_trace = parse_mem_trace(ram_trace)
    return ram_trace

def eval_dma(config_map: dict, ram_trace_path: str, mmio_trace_path: str, bb_trace_path: str):
    """
    Search for potential dma buffers, by analyzing the output traces of a given emulation run.
    First, extract dma buffer pointer candidates by analyzing the mmio trace and by searching for potential scatter-gather descriptors.
    Next, detect uninitiialized* ram reads to those pointers.
    Last, eliminate false positives and populate the output structs

    (*not only uninitialized but more to that in the according functions)

    Args:
        config_map (dict): parsed fuzzware config file
        ram_trace_path (str): path to a ram trace
        mmio_trace_path (str): path to an mmio trace
        bb_trace (str): path to a basic block trace
    Returns:
        dict(): return all dma buffer candidates, and their respective size, config and access 
                location, and config information (i.e., mmio address/scatter gather struct)
        bool:   Return True if scatter-gather dma was detected
        dict(): Return struct information on the detect scatter gather descriptors
    """
    #print(f"[*] eval_dma.py: started with {ram_trace_path} {mmio_trace_path}")
    # Extract traces
    ram_addr_ranges = extract_ram_addresses(config_map)
    mmio_addr_ranges = extract_mmio_addresses(config_map)
    ram_mem_trace = get_ram_traces(ram_trace_path)
    # read config

    # 1. Extract mmio heuristics --> i.e., ram pointers written to mmio
    mmio_written_ram_addrs, _, _, mmio_addrs_per_mmio_written_ram_addr, eventid_per_mmio_written_ram_addrs, pcs_per_mmio_written_ram_addr, all_event_ids_per_mmio_written_ram_addrs = get_mmio_written_ram_addresses(ram_addr_ranges, mmio_trace_path)
    mmio_written_ram_addrs = sorted(set(mmio_written_ram_addrs))
    debug_log(mmio_written_ram_addrs)

    # 2. extract scatter-gather heuristics
    lli_descriptors, _, _, eventid_per_descriptor_written_ram_addrs, pcs_per_descriptor_written_ram_addrs, back_descriptor = get_potential_descriptors(ram_mem_trace, ram_addr_ranges, eventid_per_mmio_written_ram_addrs, mmio_addr_ranges)

    # 3. look for uninitialized or  pre-initialized reads
    uninit_bufs_and_sizes = dumb_find_uninit_reads(ram_mem_trace, ram_addr_ranges, eventid_per_mmio_written_ram_addrs, eventid_per_descriptor_written_ram_addrs, pcs_per_mmio_written_ram_addr, pcs_per_descriptor_written_ram_addrs)
    debug_log("------------------------------------------")
    debug_log(uninit_bufs_and_sizes)

    potential_dma_ptrs = {} # Deprecaeted and needs to be removed

    # 4. Remove false posivites by comparing with scatter gather structs and mmio written ram addrs
    uninit_bufs_and_sizes, sg_bufs = dumb_false_positive_elim(mmio_written_ram_addrs, uninit_bufs_and_sizes, potential_dma_ptrs, ram_addr_ranges)
    debug_log("------------------------------------------")
    debug_log(uninit_bufs_and_sizes)
    debug_log(all_event_ids_per_mmio_written_ram_addrs)

    # 5. Clean-up and populate the output with more information, especially on the mmio register
    uninit_bufs_and_sizes = annotate_results(uninit_bufs_and_sizes, mmio_addrs_per_mmio_written_ram_addr,all_event_ids_per_mmio_written_ram_addrs, back_descriptor, lli_descriptors)
    debug_log(uninit_bufs_and_sizes)
    return uninit_bufs_and_sizes, lli_descriptors, dict()



def main(raw_args = None):
    parser = argparse.ArgumentParser()
    setup_parser(parser)
    args, leftover = parser.parse_known_args(raw_args)

    start_symbol = "main"
    if not os.path.exists(args.config):
        debug_log(f"[ERROR] Config path does not exist: '{args.config:}'"); exit(1)

    if args.log:
        set_log(args.log)

    config_map = load_config_deep(args.config)

    for trace_path in (args.mmio_trace, args.bb_trace, args.ram_trace):
        if not os.path.exists(trace_path):
            debug_log(f"[ERROR] Trace path does not exist: '{trace_path:}'"); exit(1)

    return eval_dma(config_map, args.ram_trace, args.mmio_trace, args.bb_trace)
    #return alt_eval_dma(config_map, args.ram_trace, args.mmio_trace, args.bb_trace, args.start_symbol)


    """
    debug_log("\n===== Testing detecting mechanisms  =====")
    debug_log("[*] Looking for control structs")
    potential_dma_ptrs, ext_dma_addr_predeccors, event_id_per_dma_ptr, mmio_addr_per_written_struct, pcs_per_dma_ptr, struct_interpret = find_potential_dma_structs(args.ram_trace, mmio_written_ram_addrs, ram_addr_ranges, True, mmio_addrs_per_mmio_written_ram_addr)
    debug_log(potential_dma_ptrs)
    debug_log("[*] Looking for uninitialized reads")
    uninit_bufs_and_sizes = find_uninit_reads(args.bb_trace, args.ram_trace, ram_addr_ranges, irq_address_ranges, uninit_read_addrs, eventid_per_mmio_written_ram_addrs, event_id_per_dma_ptr, pcs_per_mmio_written_ram_addr, pcs_per_dma_ptr)

    #uninit_bufs_and_sizes = find_uninit_reads(args.bb_trace, args.ram_trace, ram_addr_ranges, irq_address_ranges, uninit_read_addrs)
    debug_log(uninit_bufs_and_sizes)
    debug_log("[*] Removing false positives")
    debug_log("------------------")
    debug_log(potential_dma_ptrs)
    uninit_bufs_and_sizes, sg_bufs = false_positive_elim(mmio_written_ram_addrs, uninit_bufs_and_sizes, potential_dma_ptrs, ram_addr_ranges)
    
    debug_log(potential_dma_ptrs)
    debug_log("------------------")

    uninit_bufs_and_sizes = {**uninit_bufs_and_sizes, **sg_bufs}

    #add mmio addrs (registers) to the output
    for buf in uninit_bufs_and_sizes:
        if buf in mmio_addrs_per_mmio_written_ram_addr:
            uninit_bufs_and_sizes[buf].append(mmio_addrs_per_mmio_written_ram_addr[buf])
        elif buf in mmio_addr_per_written_struct:
            uninit_bufs_and_sizes[buf].append({mmio_addr_per_written_struct[buf]})

    debug_log(uninit_bufs_and_sizes)

    if sg_bufs:
        for addr in list(struct_interpret.keys()):
            if addr not in potential_dma_ptrs:
                struct_interpret.pop(addr)
                continue
            for off in potential_dma_ptrs[addr]:
                if potential_dma_ptrs[addr][off] in sg_bufs.keys():
                    struct_interpret[addr][off] = 'dma_buf_pointer'
    debug_log(struct_interpret)
    """

    if args.verbose:
        #TODO
        debug_log("\n===== Uninitialized Read Overlaps =====")
        overlaps = list(uninit_bufs_and_sizes.keys())
        for addr in overlaps:
            symname = ", ".join([nearest_symbol_string(ordered_symbols, pc) for pc in pcs_per_read_addr[addr]])
            debug_log(f"0x{addr:08x} (read at {symname:})")
            #log_write_path(follow_write_path(ext_dma_addr_predecessors
    
    
    return

if __name__ == '__main__':
    main()

"""
TODO: Give additional information on the read address
    1. [DONE] PC of function performing the read
    2. PC of function performing the write of the suspected MMIO pointer
    3. PCs of the chain of functions performing the writes of indirect pointers
    4. Type of read address (data section, stack, heap)
"""

