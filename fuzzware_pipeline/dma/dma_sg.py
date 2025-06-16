#!/usr/bin/env python3
from fuzzware_pipeline.dma.dma_util import *
import typing

THRESHOLD = 0x1c
HIGHSCORE_NOT_AVAILABLE = -1
threshold_steps = 0x10
def get_potential_descriptors(ram_trace: typing.List[typing.Tuple[int, int, int, str, int, int, typing.Tuple[int]]], ram_addr_ranges: list, eventid_per_mmio_written_ram_addrs: dict, mmio_addr_ranges: list):
    """
    This function analyzes mmio written RAM address to look for potential descriptor structs.
    These structs may either be Linked Lists or Array Lists (So far we only implement Linked Lists)

    Step 1: Given a MMIO written RAM address collect all writes to address in a THRESHOLD range arround that address
    Step 2: Categorize the collected writes depending on the written values
    Step 3: If there were at least to RAM pointers present in a descriptor candidate we keep it as it might be a linked list item.
            Then follow the pointers and check wether there is a similar struct located at that destination.
    Step 4: If that does not succeed, we try to find a descriptor struct, with the same structure as our candidate that holds apointer to our candidate.
            This might be the case if only the last descriptor item is referenced from MMIO
    Step 5: If there is a match, collect all Buffer pointer from these structs and return the pointers with some metadata

    TODO: We probably only want to look at writes that were happening up until a certain eventid?
            This is easy first, but gets harder when backtracing for descriptros

    Args:
    Return:
    """
    if not eventid_per_mmio_written_ram_addrs:
        return dict(), dict(), dict(), dict(), dict(), dict()
    all_eventid_per_pointer_write = dict()
    eventid_per_pointer_write = dict()
    all_pc_per_pointer_write = dict()
    pc_per_pointer_write = dict()
    address_to_struct = dict()
    addr_per_ram_written_ram_ptr = dict() # {addr: [{ptr: xx, eventid: xx}]}
    ram_written_ram_ptr = set()
    highest_evt_id = max(list(eventid_per_mmio_written_ram_addrs.values()))
    reduced_ram_trace = list()
    # Step 1: Go thoruhg the RAM trace and collect writes at candidate addrs
    candidate_addrs = dict([(base_addr+i, base_addr) for base_addr in eventid_per_mmio_written_ram_addrs for i in range(-THRESHOLD, THRESHOLD + 4, 4) if base_addr & 0x3 == 0])
    if not candidate_addrs:
        return dict(), dict(), dict(), dict(), dict(), dict()
  
    for i, (event_id, pc, lr, mode, size, address, val_text) in enumerate(ram_trace):
        if event_id > highest_evt_id * 2:
            break
        if i + 1 < len(ram_trace) and pc == ram_trace[i+1][1]:
            # skip stack pushing and popping
            continue

        if mode == "r":
            continue
        reduced_ram_trace.append((event_id, pc, lr, mode, size, address, val_text))

        cur_val = get_val(val_text)
        if  cur_val in eventid_per_mmio_written_ram_addrs:
            ram_written_ram_ptr.add(cur_val)
            if address in addr_per_ram_written_ram_ptr:
                addr_per_ram_written_ram_ptr[address][event_id] = cur_val
            else:
                addr_per_ram_written_ram_ptr[address] = {event_id: cur_val}

        if address in candidate_addrs:
            if candidate_addrs[address] not in address_to_struct:
                address_to_struct[candidate_addrs[address]] = dict()

            if address in  address_to_struct[candidate_addrs[address]]:
                last_added = address
                address_to_struct[candidate_addrs[address]][address].append(cur_val)
                all_eventid_per_pointer_write[address].append(event_id)
                all_pc_per_pointer_write[address].append(pc)
            else: 
                last_added = address
                address_to_struct[candidate_addrs[address]][address] = [cur_val]
                all_eventid_per_pointer_write[address] = [event_id]
                all_pc_per_pointer_write[address] = [pc]
            continue

    # Step 2: Assign descriptions to the individual fields of the descriptor candidates
    #         As we do not know the size of the struct, gradually increase it
    best_descriptors = dict()
    best_scores = dict()
    all_descriptions = dict()
    all_structs = dict()
    ll_description_candidates = dict()
    ll_backward_candidates = dict()
    threshold_checking = list(range(threshold_steps, THRESHOLD, threshold_steps))
    threshold_checking.append(THRESHOLD)
    for cur_threshold in threshold_checking:
        log(f"*********************{cur_threshold:#x}")
        # For a given descriptor size categorize all writes 
        # As we do not know wether the MMIO written RAM pointer, points to the end or the start of the descriptor, we look in both directions
        for base_addr, members in address_to_struct.items():
            backward_pointers = all_descriptions[base_addr][BPOINTERS] if base_addr in all_descriptions and BPOINTERS in all_descriptions[base_addr] else dict()
            backward_description = all_descriptions[base_addr][BACKWARD] if base_addr in all_descriptions and BACKWARD in all_descriptions[base_addr] else dict()
            forward_pointers = all_descriptions[base_addr][FPOINTERS] if base_addr in all_descriptions and FPOINTERS in all_descriptions[base_addr] else dict() 
            forward_description = all_descriptions[base_addr][FORWARD] if base_addr in all_descriptions and FORWARD in all_descriptions[base_addr] else dict() 
            forward_struct = dict()
            backward_struct = dict()
            cleaned_struct = all_structs[base_addr] if  base_addr in all_structs else dict()
            log("==============================")
            log(f"baseaddr is {base_addr:#x}")

            # Populate mssining write entries
            for i in range(-cur_threshold, cur_threshold + 4, 4):
                if i in backward_description or i in forward_description:
                    continue        
                address = base_addr + i
                if address not in members:
                    writes = [-1]
                else:
                    writes = members[address]
                log(f"{address:#x}: {','.join(hex(x) for x in writes)}")
                if i <= 0:
                    backward_struct[address] = list(writes)
                if i >= 0:
                    forward_struct[address] = list(writes)

            # Categorize backwards
            for address, writes in backward_struct.items():
                if address - base_addr in backward_description:
                    continue
                if len(writes) == 1 and writes[0] == -1:
                    backward_description[address - base_addr] = UNDEFINED
                    continue
                # PATCH instead of al writes only last one
                # for write in writes
                write = writes[-1]
                #log(f"{address:#x} : {write:#x}")
                cleaned_struct[address] = write
                eventid_per_pointer_write[address] = all_eventid_per_pointer_write[address][writes.index(write)]
                pc_per_pointer_write[address] = all_pc_per_pointer_write[address][writes.index(write)]
                if write == 0:
                    backward_description[address - base_addr] = NULL
                    continue
                elif in_range(ram_addr_ranges, write):
                    backward_description[address - base_addr] = POINTER
                    backward_pointers[write] = address - base_addr
                    
                elif in_range(mmio_addr_ranges, write):
                    backward_description[address - base_addr] = MMIO_REG
                    
                else:
                    backward_description[address - base_addr] = NON_ZERO
            
            log(backward_description)
            
            # Categorize forward
            for address, writes in forward_struct.items():
                if address - base_addr in forward_description:
                    continue
                if len(writes) == 1 and writes[0] == -1:
                    forward_description[address - base_addr] = UNDEFINED
                    continue
                #for write in writes:
                write = writes[-1]
                cleaned_struct[address] = write
                eventid_per_pointer_write[address] = all_eventid_per_pointer_write[address][writes.index(write)]
                pc_per_pointer_write[address] = all_pc_per_pointer_write[address][writes.index(write)]
                if write == 0:
                    forward_description[address - base_addr] = NULL
                    continue
                elif in_range(ram_addr_ranges, write):
                    forward_description[address - base_addr] = POINTER
                    forward_pointers[write] = address - base_addr
                    continue
                elif in_range(mmio_addr_ranges, write):
                    forward_description[address - base_addr] = MMIO_REG
                    continue
                else:
                    forward_description[address - base_addr] = NON_ZERO

            log(forward_description)
            
            # Check if there is 2 or more pointers in either of the structs. If yes keep them as candidates for further analysis
            if list(forward_description.values()).count(POINTER) > 1:
                if list(backward_description.values()).count(POINTER) > 1:
                    ll_description_candidates[base_addr] = {FORWARD: forward_description, FPOINTERS: forward_pointers, 
                                        BACKWARD: backward_description, BPOINTERS: backward_pointers}
                else:
                    ll_description_candidates[base_addr] = {FORWARD: forward_description, FPOINTERS: forward_pointers, 
                                        BACKWARD: {}, BPOINTERS: {}}
            elif list(backward_description.values()).count(POINTER) > 1:
                ll_description_candidates[base_addr] = {FORWARD: {}, FPOINTERS: {}, 
                                        BACKWARD: backward_description, BPOINTERS: backward_pointers}
                
            # Check if there is 1 or more pointers in either of the structs. If yes keep them as candidates for further analysis
            if base_addr in ram_written_ram_ptr:
                if list(forward_description.values()).count(POINTER) > 0:
                    if list(backward_description.values()).count(POINTER) > 0:
                        ll_backward_candidates[base_addr] = {FORWARD: forward_description, FPOINTERS: forward_pointers, 
                                            BACKWARD: backward_description, BPOINTERS: backward_pointers}
                    else:
                        ll_backward_candidates[base_addr] = {FORWARD: forward_description, FPOINTERS: forward_pointers, 
                                            BACKWARD: {}, BPOINTERS: {}}
                elif list(backward_description.values()).count(POINTER) > 0:
                    ll_backward_candidates[base_addr] = {FORWARD: {}, FPOINTERS: {}, 
                                            BACKWARD: backward_description, BPOINTERS: backward_pointers}

            all_descriptions[base_addr] = {FORWARD: forward_description, FPOINTERS: forward_pointers, 
                                        BACKWARD: backward_description, BPOINTERS: backward_pointers}  
            all_structs[base_addr] = cleaned_struct

        # If no candidates were found within the current threshold, continue
        log("LL candidates")
        log(ll_description_candidates)
        log(ll_backward_candidates)
        if not ll_description_candidates: 
            continue

        # TODO maybe also output resuting buffer candidates for later?
        # Calculate match scores for the descriptors
        ll_best, ll_offset, ll_score = match_descriptions(reduced_ram_trace, ram_addr_ranges, mmio_addr_ranges, ll_description_candidates)

        log("MATCH RESULTS:")
        log(ll_best)
        log(ll_offset)
        log(ll_score)


        # extract the best descriptor for the current threshold
        best_descriptors[cur_threshold] = dict([(base_addr, field) for base_addr, descriptors in ll_description_candidates.items() for direction, field in descriptors.items() if base_addr in ll_best and direction in ll_best[base_addr]])
        best_scores[cur_threshold] = ll_score

    # Check if there is a descriptor match
    pointer_candidates = set()
    base_addr_per_pointer_candidate = dict()
    eventid_per_buffer_addr = dict()
    pc_per_buffer_addr = dict()
    cmp_percentage = 0.5 # at least 50 percent match
    best_threshold = -1
    for threshold, score in best_scores.items():
        # max score is the number of elements --> (max_threshod // 4) + 1
        if score > cmp_percentage:
            best_threshold = threshold
            break

    if best_threshold == -1:
        # Found nothing so far. Lets try to look backward
        if not ll_backward_candidates:
            return dict(), dict(), dict(), dict(), dict(), dict()
        score, direction, backtrace_descr, new_descr, ll_offset_cand = backtrace_descriptor(reduced_ram_trace, ram_addr_ranges, addr_per_ram_written_ram_ptr, ll_backward_candidates, mmio_addr_ranges, eventid_per_mmio_written_ram_addrs)
        
        if score < cmp_percentage:
            return dict(), dict(), dict(), dict(), dict(), dict()
        
        best_descriptor = {backtrace_descr: all_descriptions[backtrace_descr][direction]}
        log(best_descriptor)
        log(ll_offset_cand)
        # Set the Linked List pointer descriotion
        if ll_offset_cand:
            best_descriptor[backtrace_descr][ll_offset_cand] = LLI_PTR
        log(best_descriptor)

        # Collect pointer offsets
        for base_addr, field in best_descriptor.items():
            assert(base_addr in all_structs)
            pointers = [x for x,y in field.items() if y == "pointer"]  
            base_addr_per_pointer_candidate.update(dict([(base_addr, {'addr': all_structs[base_addr][base_addr + x], 'offset': x}) for x in pointers]))

        # Extract all dma buffer pointer values by walking the descriptors
        all_pointers_and_meta_info = dict()
        for base_addr, field in best_descriptor.items():
            all_pointers_and_meta_info.update(walk_descriptor(field, new_descr, new_descr, reduced_ram_trace, ram_addr_ranges, eventid_per_mmio_written_ram_addrs[base_addr]))
        log(best_descriptor)
        log(eventid_per_mmio_written_ram_addrs[backtrace_descr])
        
        pointer_candidates = set([field['val'] for base_addr, field in all_pointers_and_meta_info.items()])
        eventid_per_buffer_addr = dict([(field['val'], field['eventid']) for base_addr, field in all_pointers_and_meta_info.items()])
        pc_per_buffer_addr = dict([(field['val'], {'pc': field['pc'], 'from': base_addr, 'base': field['initial']}) for base_addr, field in all_pointers_and_meta_info.items()])

        log("ALL POINTERS")
        log(", ".join([hex(x) for x in pointer_candidates]))    
        # return everything
        backward_match = {new_descr: backtrace_descr}
        return best_descriptor, base_addr_per_pointer_candidate, pointer_candidates, eventid_per_buffer_addr, pc_per_buffer_addr, backward_match


    # Found a descirptor match without backtracing (yeah)
    # First set the LLI descriptions and extract pointer offsets
    log(f"Winning threshold is: {best_threshold:#x}")
    best_descriptor = best_descriptors[best_threshold]
    remove_descriptor_list = list()
    for base_addr, field in best_descriptor.items():
        log(f"Winner base addr is {base_addr:#x}")
        log(f"field is {field}")
        for offset in list(field.keys()):
            if offset > best_threshold:
                field.pop(offset)

        assert(base_addr in all_structs)
        if base_addr in ll_offset:
            field[ll_offset[base_addr]] = LLI_PTR
        else:
            remove_descriptor_list.append(base_addr)
            continue
        pointers = [x for x,y in field.items() if y == "pointer"]
        
        base_addr_per_pointer_candidate.update(dict([(base_addr, {'addr': all_structs[base_addr][base_addr + x], 'offset': x}) for x in pointers]))

    for addr in remove_descriptor_list:
        log(f"Removing {addr}")
        best_descriptor.pop(addr)
    log(best_descriptor)
    if not best_descriptor:
        return dict(), dict(), dict(), dict(), dict(), dict()


    # Walk the descriptors to extract dma buffer pointer vals 
    all_pointers_and_meta_info = dict()
    for base_addr, field in best_descriptor.items():
        all_pointers_and_meta_info.update(walk_descriptor(field, base_addr, base_addr, reduced_ram_trace, ram_addr_ranges, eventid_per_mmio_written_ram_addrs[base_addr]))
    


    pointer_candidates = set([field['val'] for base_addr, field in all_pointers_and_meta_info.items()])
    eventid_per_buffer_addr = dict([(field['val'], field['eventid']) for base_addr, field in all_pointers_and_meta_info.items()])
    pc_per_buffer_addr = dict([(field['val'], {'pc': field['pc'], 'from': base_addr, 'base': field['initial']}) for base_addr, field in all_pointers_and_meta_info.items()])
    log(pointer_candidates)
    log(eventid_per_buffer_addr)
    
    # return everything
    return best_descriptor, base_addr_per_pointer_candidate, pointer_candidates, eventid_per_buffer_addr, pc_per_buffer_addr, dict()



def walk_descriptor(description: dict, current_start: int, initial_start: int, ram_trace: list, ram_addr_ranges: list, cutoff_event_id: int) -> set:
    """
    Recursively walk a LL descriptor struct and collect all non LLI item pointers, and follow th LLI pointers

    Args:
        description (dict):
        current_start (int):
        initial_start (int):
        ram_trace (list):
        ram_addr_ranges (list):
        cutoff_Event_id (int):

    Returns:
        set(): Pointer found in descriptor list
    """
    #log("WALKING")
    pointer_addresses = [current_start + offset for offset, entry_type in description.items() if entry_type == POINTER]
    lli_addresses = [current_start + offset for offset, entry_type in description.items() if entry_type == LLI_PTR]

    pointer_vals = dict()
    lli_vals = dict()

    for event_id, pc, lr, mode, size, address, val_text in ram_trace:
        if event_id >= cutoff_event_id:
            break
        if address in pointer_addresses and in_range(ram_addr_ranges, get_val(val_text)):
            #log(f"got {address:#x} : {val_text}")
            pointer_vals[address] = {'val': get_val(val_text), 'pc': pc, 'eventid': event_id, 'initial': initial_start}
        if address in lli_addresses:
            if in_range(ram_addr_ranges, get_val(val_text)):
                lli_vals[address] = get_val(val_text)
            elif get_val(val_text) == 0:
                lli_vals[address] = 0


    #log(lli_vals)
    if not lli_vals:
        return pointer_vals

    if lli_vals[lli_addresses[0]] == initial_start or lli_vals[lli_addresses[0]] == 0 or lli_vals[lli_addresses[0]] == current_start:
        return pointer_vals
    log(f"next: {lli_vals[lli_addresses[0]]:#x}, intiial start is {initial_start:#x}")
    current_pointers = pointer_vals
    recursive_pointers = walk_descriptor(description, lli_vals[lli_addresses[0]], initial_start, ram_trace, ram_addr_ranges, cutoff_event_id)
    current_pointers.update(recursive_pointers)
    return current_pointers

def print_all_backtrace_scores(backtrace: dict, ll_descriptions: dict):
    """ Debug utility """
    log("[+++] sorting scores...")
    highest_score = list()
    for descr_addr, entry in backtrace.items():
        for other_descriptor, field in entry.items():
            for direction, score in field.items():
                    highest_score.append((score, direction, other_descriptor, descr_addr))
    
    highest_score = sorted(highest_score, key=lambda x: x[0])
    for score, direction, other_descriptor, descr_addr in highest_score:
        log(f"[+++] score: {score}, direction {direction}, existing_descr {other_descriptor:#x}, new descriptor {descr_addr:#x}")
        log(ll_descriptions[descr_addr][direction])

    log("[+++] done")
        
        

def backtrace_descriptor(ram_trace: list, ram_addr_ranges: list, ram_written_ram_ptr: dict, existing_descriptions: dict, mmio_addr_ranges: list, event_id_per_mmio_written_ram_addrs):
    """
    Given different descriptors, search the ram trace to look for descriptors preceeding that descriptor. Verify if the descriptions match.
    Step 1: Extract the pointer and NULL offsets of each existing description
    Step 2: Given a list of RAM written RAM pointers to potential structs, extract all potential base address for the pointer by shifting by the Step 1 offsets
    Step 3: Go through the RAM trace and extract all writes in [+THRESHOLD, -THRESHOLD] around  the base addr candidates
    Step 4: Annotate the new descriptor candidates the way the existing descriptions are annotated
    Step 6: Compare the descriptions of all new descriptor candidates with the descriptions they point towards
    Step 7: Check the match scores of all candidates and pick the best one

    Args:
        ram_trace (list):
        ram_addr_ranges (list):
        ram_written_ram_ptr (dict):
        existing_descriptions (dict):
        mmio_addr_ranges (list):

    Return:
        int: score 
        str: direction
        int: existing_descriptor
        int: (backtraced) descr_add
        int: offset of the linked list pointer 

    """
    candidate_addrs = dict()
    pointers_per_description = dict()
    # Step 1 Get all offsets of pointers for each descriptor element
    for addr, entry in existing_descriptions.items():
        pointers_per_description[addr] = set()
        for offset, descr_type in {**entry[FORWARD], **entry[BACKWARD]}.items():
            if descr_type not in  [POINTER, NULL]:
                continue
            pointers_per_description[addr].add(offset)


    # Step 2
    potential_derived_struct = dict()
    pointer_and_potential_original_structs = dict()
    for base_addr, entries in ram_written_ram_ptr.items():
        for event_id, val in entries.items():
            if val not in pointers_per_description:
                continue
            for pointer in pointers_per_description[val]:
            
                if base_addr - pointer in potential_derived_struct:
                    if pointer in potential_derived_struct[base_addr - pointer]:
                        continue
                    potential_derived_struct[base_addr - pointer][pointer] = base_addr
                    
                else:
                    potential_derived_struct[base_addr - pointer] = {pointer: base_addr}
                if val not in pointer_and_potential_original_structs:
                    pointer_and_potential_original_structs[val] = [base_addr - pointer]
                else:
                    pointer_and_potential_original_structs[val].append(base_addr - pointer)
                #log(f"\t {val:#x} could be pointed to from struct @ {base_addr - pointer:#x}")


    log([hex(y) for y in sorted([x for x in potential_derived_struct])])

    # Step 3
    all_eventid_per_pointer_write = dict()
    eventid_per_pointer_write = dict()
    all_pc_per_pointer_write = dict()
    pc_per_pointer_write = dict()
    candidate_addrs = dict([(base_addr+i, base_addr) for base_addr in potential_derived_struct for i in range(-THRESHOLD, THRESHOLD + 4, 4)])
    base_addr_to_candidate_addr =  dict([(base_addr, [base_addr + i for i in range(-THRESHOLD, THRESHOLD + 4, 4)]) for base_addr in potential_derived_struct if base_addr not in existing_descriptions])
    address_to_struct = dict()
    
    for i in range(len(ram_trace)):
        event_id, pc, lr, mode, size, address, val_text = ram_trace[i]
        if i + 1 < len(ram_trace) and pc == ram_trace[i+1][1]:
            # skip stack pushing and popping
            continue
        if mode == "r":
            continue
        
        if address in candidate_addrs:
            for base_address, elements in base_addr_to_candidate_addr.items():
                if address not in elements:
                    continue
            
                if base_address not in address_to_struct:
                    address_to_struct[base_address] = dict()

                if address in  address_to_struct[base_address]:
                    last_added = address
                    address_to_struct[base_address][address].append(get_val(val_text))
                    all_eventid_per_pointer_write[address].append(event_id)
                    all_pc_per_pointer_write[address].append(pc)
                else: 
                    last_added = address
                    address_to_struct[base_address][address] = [get_val(val_text)]
                    all_eventid_per_pointer_write[address] = [event_id]
                    all_pc_per_pointer_write[address] = [pc]
                continue
    
    # Step 4
    ll_description_candidates = dict()
    all_structs = dict()
    all_descriptions = dict()    
    for base_addr, members in address_to_struct.items():
        backward_pointers = dict()
        backward_description = dict()
        forward_pointers = dict() 
        forward_description = dict() 
        forward_struct = dict()
        backward_struct = dict()
        cleaned_struct = dict()
        log("==============================")
        log(f"baseaddr is {base_addr:#x}")
        for i in range(-THRESHOLD, THRESHOLD + 4, 4):
            if i in backward_description or i in forward_description:
                continue        
            address = base_addr + i
            if address not in members:
                writes = [-1]
            else:
                writes = members[address]
            if i <= 0:
                backward_struct[address] = list(writes)
            if i >= 0:
                forward_struct[address] = list(writes)

        # now we want to go through the forward and backward struct and check whether we point to other potential struct candidates
        for address, writes in backward_struct.items():
            if address - base_addr in backward_description:
                continue
            if len(writes) == 1 and writes[0] == -1:
                backward_description[address - base_addr] = UNDEFINED
                continue
            #for write in writes:
            write = writes[-1]
            cleaned_struct[address] = write
            eventid_per_pointer_write[address] = all_eventid_per_pointer_write[address][writes.index(write)]
            pc_per_pointer_write[address] = all_pc_per_pointer_write[address][writes.index(write)]
            if write == 0:
                backward_description[address - base_addr] = NULL
                continue
            elif in_range(ram_addr_ranges, write):
                backward_description[address - base_addr] = POINTER
                backward_pointers[write] = address - base_addr
                continue
            elif in_range(mmio_addr_ranges, write):
                backward_description[address - base_addr] = MMIO_REG
                continue
            else:
                backward_description[address - base_addr] = NON_ZERO
        
        log(backward_description)
        
        #log(forward_struct)
        for address, writes in forward_struct.items():
            if address - base_addr in forward_description:
                continue
            if len(writes) == 1 and writes[0] == -1:
                forward_description[address - base_addr] = UNDEFINED
                continue
            #for write in writes:
            write = writes[-1]
            cleaned_struct[address] = write
            eventid_per_pointer_write[address] = all_eventid_per_pointer_write[address][writes.index(write)]
            pc_per_pointer_write[address] = all_pc_per_pointer_write[address][writes.index(write)]
            if write == 0:
                forward_description[address - base_addr] = NULL
                continue
            elif in_range(ram_addr_ranges, write):
                forward_description[address - base_addr] = POINTER
                forward_pointers[write] = address - base_addr
                continue
            elif in_range(mmio_addr_ranges, write):
                forward_description[address - base_addr] = MMIO_REG
                continue
            else:
                forward_description[address - base_addr] = NON_ZERO
        log(forward_description)
        if list(forward_description.values()).count(POINTER) > 1:
            if list(backward_description.values()).count(POINTER) > 1:
                ll_description_candidates[base_addr] = {FORWARD: forward_description, FPOINTERS: forward_pointers, 
                                    BACKWARD: backward_description, BPOINTERS: backward_pointers}
            else:
                ll_description_candidates[base_addr] = {FORWARD: forward_description, FPOINTERS: forward_pointers, 
                                    BACKWARD: {}, BPOINTERS: {}}
        elif list(backward_description.values()).count(POINTER) > 1:
            ll_description_candidates[base_addr] = {FORWARD: {}, FPOINTERS: {}, 
                                    BACKWARD: backward_description, BPOINTERS: backward_pointers}

        all_descriptions[base_addr] = {FORWARD: forward_description, FPOINTERS: forward_pointers, 
                                    BACKWARD: backward_description, BPOINTERS: backward_pointers}  
        all_structs[base_addr] = cleaned_struct


    # Step 5
    lli_cands = dict([(x, dict()) for x in ll_description_candidates])
    match_scores = dict()
    for descr_addr, potential_description in ll_description_candidates.items():
        # base address refers to a potential struct.
        # now we need to extract the struct(s) this struct might lonk to
        log("=========================================")
        log(hex(descr_addr))
        #log(base_addr_to_candidate_addr[base_addr])
        checked_addr = list()
        for pointer, addr in potential_derived_struct[descr_addr].items():
            
            #log(f"{descr_addr:#x} struct points to {ram_written_ram_ptr[addr]}")
            for existing_base_addr in set(list(ram_written_ram_ptr[addr].values())):
                if existing_base_addr == descr_addr:
                    continue
                if existing_base_addr in checked_addr:
                    continue
                checked_addr.append(existing_base_addr)
                #TODO disallow overlapping of descriptors 
                log("-----")
                log(f"\tCOMPARING {descr_addr:#x} with  {existing_base_addr:#x}")
                # First forward comparison
                match_existing_forward_description = existing_descriptions[existing_base_addr][FORWARD] if existing_base_addr in existing_descriptions and FORWARD in existing_descriptions[existing_base_addr] else dict()
                match_existing_backward_description = existing_descriptions[existing_base_addr][BACKWARD] if existing_base_addr in existing_descriptions and BACKWARD in existing_descriptions[existing_base_addr] else dict()
                forward_description = potential_description[FORWARD]
                backward_description = potential_description[BACKWARD]

                matches = 0
                ptr_null_matches = 0

                # Only do comparison up to the pointer with the highest offset. 
                last_pointer = max([x for x, descr_typ in forward_description.items() if descr_typ == POINTER]) if POINTER in forward_description.values() else 0
                if descr_addr < existing_base_addr and descr_addr + THRESHOLD > existing_base_addr:
                    last_pointer = (existing_base_addr - descr_addr) - 4 if (existing_base_addr -descr_addr) -4 < last_pointer else last_pointer
                if existing_base_addr < descr_addr and existing_base_addr + THRESHOLD >= descr_addr:
                    last_pointer = (descr_addr - existing_base_addr) - 4 if (descr_addr - existing_base_addr) - 4 < last_pointer else last_pointer


                
                # TODO maybe comparison into individual functions????
                if (match_existing_forward_description.keys() == forward_description.keys()):
                    for offset in match_existing_forward_description:
                        if offset > last_pointer:
                            break
                        log(f"offset {offset:#x}: {forward_description[offset]} ?= {match_existing_forward_description[offset]}")
                        if (descr_addr + offset) in all_structs[descr_addr] and all_structs[descr_addr][descr_addr + offset] == existing_base_addr:
                            ptr_null_matches += 1
                            lli_cands[descr_addr][existing_base_addr] = offset
                        
                        if match_existing_forward_description[offset] == forward_description[offset]:
                            if match_existing_forward_description[offset] == NON_ZERO:
                                matches -= 0.5
                            matches += 1
                            continue # got a match nice
                        
                
                fw_matches = 0
                if matches and last_pointer > 0x4 and existing_base_addr in lli_cands[descr_addr]:
                    log(lli_cands[descr_addr][existing_base_addr])
                    log(f"\t\tMatches: {(matches + 0.5 * ptr_null_matches)} -- {(last_pointer // 4) + 1}")
                    fw_matches = (matches + 0.5 * ptr_null_matches) / ((last_pointer // 4) + 1)

                last_pointer = min([x for x, descr_typ in backward_description.items() if descr_typ == POINTER]) if POINTER in backward_description.values() else 0
                if descr_addr > existing_base_addr and descr_addr - THRESHOLD <= existing_base_addr:
                    last_pointer = (existing_base_addr -descr_addr) + 4 if (existing_base_addr - descr_addr) + 4 > last_pointer else last_pointer
                if existing_base_addr > descr_addr and existing_base_addr - THRESHOLD <= descr_addr:
                    last_pointer = (descr_addr -existing_base_addr) + 4 if (descr_addr - existing_base_addr) + 4 > last_pointer else last_pointer
                matches = 0
                ptr_null_matches = 0
                if match_existing_backward_description.keys() == backward_description.keys():
                    for offset in match_existing_backward_description:
                        if offset < last_pointer:
                            break
                        if (descr_addr + offset) in all_structs[descr_addr] and all_structs[descr_addr][descr_addr + offset] == existing_base_addr:
                            ptr_null_matches += 1
                            lli_cands[descr_addr][existing_base_addr] = offset
                        log(f"offset {offset:#x}: {backward_description[offset]} ?= {match_existing_backward_description[offset]}")
                        if match_existing_backward_description[offset] == backward_description[offset]:
                            if match_existing_backward_description[offset] == NON_ZERO:
                                matches -= 0.5
                            matches += 1
                            continue # got a match nice
        
                
                bw_matches = 0
                if matches and last_pointer < -0x4 and existing_base_addr in lli_cands[descr_addr] and lli_cands[descr_addr][existing_base_addr] <= 0:
                    log(lli_cands[descr_addr][existing_base_addr])
                    log(f"\t\tMatches: {(matches + 0.5 * ptr_null_matches)} -- {(abs(last_pointer) // 4) + 1}")
                    bw_matches = (matches + 0.5 * ptr_null_matches) / ((abs(last_pointer) // 4) + 1)
            
                if bw_matches < 0:
                    bw_matches = 0
                if fw_matches < 0:
                    fw_matches = 0

                # Sore the matches
                if descr_addr not in match_scores:
                    match_scores[descr_addr] = {existing_base_addr: {FORWARD: fw_matches, BACKWARD: bw_matches}}
                else:
                    match_scores[descr_addr][existing_base_addr] = {FORWARD: fw_matches, BACKWARD: bw_matches}
                
                # Debug
                
                log("\tForward")
                log(f"\t{match_existing_forward_description}")
                log(f"\t{forward_description}")
                log(f"\t==> {fw_matches}")

                log("\tBackward")
                log(f"\t{match_existing_backward_description}")
                log(f"\t{backward_description}")
                log(f"\t==> {bw_matches}")


    # Step 6
    highest_score = (-1,-1,-1, -1)
    for descr_addr, entry in match_scores.items():
        for existing_descriptor, field in entry.items():
            for direction, score in field.items():
                if score > highest_score[0]:
                    highest_score = (score, direction, existing_descriptor, descr_addr)

    if highest_score[0] >= 0.7:    
        # Debug 
        log(lli_cands)
        log(f"score: {highest_score[0]}, direction {highest_score[1]}, existing_descr {highest_score[2]:#x}, new descriptor {highest_score[3]:#x}")
        log(ll_description_candidates[highest_score[3]][highest_score[1]])
        log(existing_descriptions[highest_score[2]][highest_score[1]])
        log("====================")

    # Here we might want to add a minimum threshold
    if highest_score[0] < 0.7: 
        # No suting candidate found
        return -1, -1, -1, -1, -1

    # patch description if descriptions overlap; two cases
    """ 
    Case 1                                                                                        
    +-----------------+
    | new descr/      |
    | existing desc+--+-----------------+
    +--------------+--+ exsiting descr/ |
                   |    new descr       |
                   +--------------------+
    """
    log(existing_descriptions[highest_score[2]][highest_score[1]])
    if highest_score[1] == FORWARD:
        if highest_score[3] < highest_score[2] and highest_score[3] + THRESHOLD > highest_score[2]:
            for i in range(0, THRESHOLD + 4, 4):
                if highest_score[3] + i >= highest_score[2]:
                    existing_descriptions[highest_score[2]][highest_score[1]].pop(i)
    elif highest_score[1] == BACKWARD:
         if highest_score[3] > highest_score [2] and highest_score[3] - THRESHOLD < highest_score[2]:
            for i in range(0, THRESHOLD + 4, 4):
                if highest_score[3] - i <= highest_score[2]:
                    existing_descriptions[highest_score[2]][highest_score[1]].pop(i)

    log(existing_descriptions[highest_score[2]][highest_score[1]])

    # return score, direction, existing_descr, new_desr, ll_cand
    return highest_score[0], highest_score[1], highest_score[2], highest_score[3], lli_cands[highest_score[3]][highest_score[2]]



def base_addr_from_pointer(descriptions, pointer):
    for base_addr, field in descriptions:
        if pointer in field[BPOINTERS]:
            return field[BPOINTERS][pointer]
        if pointer in field[FPOINTERS]:
            return field[FPOINTERS][pointer]
    return -1

def match_descriptions(ram_trace: list, ram_addr_ranges: list, mmio_addr_ranges: list, descriptions: list):
    """
    Given some potential DMA descriptors (and their annotations) follow their pointers and check if there is a similar struct at the 
    referenced memory. This is a sign that it is actually a linked list item.
    Step 1: Given some potential descriptors, extract all pointers and store them as potential new descriptor base addrs
    Step 2: Go through the RAM trace and extract all writes in [+THRESHOLD, -THRESHOLD] around  the base addr candidates
    Step 3: Annotate the new descriptor candidates the way the existing descriptions are annotated
    Step 4: Compare the descriptions of all new descriptor candidates with the descriptions they point towards
    Step 7: Check the match scores of all candidates and pick the best one

    Args:
        ram_trace (list):
        ram_addr_ranges(list):
        mmio_addr_ranges (list):
        descriptions (list):
    Returns:
        int: Score of the best matching descriptor (between 0 and 1)
        dict(): Descriptor base addresses and their directions (forward/backward)
        dict(): Descriptor base addresses and the offset of the linked list pointer
    """
    log("#+#+#+#+#+#+#++#+#+#+#+#+#+#+#+#+#")
    log(f"MATCH DESCRIPTION: {descriptions}")
    # Step 1
    address_to_struct = dict()
    candidate_addrs = dict()
    ptr_to_base_addr = dict()

    cur_threshold = max(descriptions[next(iter(descriptions))][FORWARD]) if FORWARD in descriptions[next(iter(descriptions))] and descriptions[next(iter(descriptions))][FORWARD] else max(descriptions[next(iter(descriptions))][BACKWARD])
    log(f"cur threshold is {cur_threshold:#x}")
    for base_addr, field in descriptions.items():
        for pointer in list(field[BPOINTERS].keys()) + list(field[FPOINTERS].keys()):
            # store pointer -> base address association
            if pointer not in ptr_to_base_addr:
                ptr_to_base_addr[pointer] = {base_addr} 
            else:
                ptr_to_base_addr[pointer].add(base_addr)

            # Extract the descriptor range around the pointers
            for i in range(-cur_threshold, cur_threshold + 4, 4):
                if pointer + i in candidate_addrs:
                    candidate_addrs[pointer + i].add(pointer)
                    continue
                candidate_addrs[pointer + i] = {pointer}
    
    # Step 2
    for event_id, pc, lr, mode, size, address, val_text in ram_trace:
        if mode == "r":
            continue
        if address in candidate_addrs:
            for base_addr in candidate_addrs[address]:
                if base_addr not in address_to_struct:
                    address_to_struct[base_addr] = dict()

                if address in  address_to_struct[base_addr]:
                    address_to_struct[base_addr][address].append(get_val(val_text))
                else: 
                    address_to_struct[base_addr][address] = [get_val(val_text)]

    # Step 3
    match_scores = dict()
    lli_cands = dict()
    for descriptor_addr, members in address_to_struct.items():
        #log(f"==================={descriptor_addr:#x}")
        #log(f"{descriptor_addr:#x} --> {ptr_to_base_addr[descriptor_addr]}")
        forward_struct = dict()
        backward_struct = dict()

        for i in range(-cur_threshold, cur_threshold + 4, 4):           
            address = descriptor_addr + i
            if address not in members:
                writes = [-1]
            else:
                writes = members[address]
            #log(f"{address:#x}: {','.join(hex(x) for x in writes)}")
            if i <= 0:
                backward_struct[address] = list(set(writes))
            if i >= 0:
                forward_struct[address] = list(set(writes))

        # TODO sets might be fine?

        # now we want to go through the forward and backward struct and check whether we point to other potential struct candidates
        backward_pointers = dict()
        backward_description = dict()
        for address, writes in backward_struct.items():
            if len(writes) == 1 and writes[0] == -1:
                backward_description[address - descriptor_addr] = UNDEFINED
                continue
            #for write in writes:
            write = writes[-1]
                #log(f"{address:#x} : {write:#x}")
            if write == 0:
                backward_description[address - descriptor_addr] = NULL
                continue
            elif in_range(ram_addr_ranges, write):
                backward_description[address - descriptor_addr] = POINTER
                backward_pointers[write] = address - descriptor_addr
                continue
            elif in_range(mmio_addr_ranges, write):
                backward_description[address - descriptor_addr] = MMIO_REG
                continue
            else:
                backward_description[address - descriptor_addr] = NON_ZERO
        
        #log(backward_description)
        forward_pointers = dict()
        forward_description = dict()
        #log(forward_struct)
        for address, writes in forward_struct.items():
            if len(writes) == 1 and writes[0] == -1:
                forward_description[address - descriptor_addr] = UNDEFINED
                continue
            #for write in writes:
            write = writes[-1]
            #log(f"{address:#x} : {write:#x}")
            if write == 0:
                forward_description[address - descriptor_addr] = NULL
                continue
            elif in_range(ram_addr_ranges, write):
                forward_description[address - descriptor_addr] = POINTER
                forward_pointers[write] = address - descriptor_addr
                continue
            elif in_range(mmio_addr_ranges, write):
                forward_description[address - descriptor_addr] = MMIO_REG
                continue
            else:
                forward_description[address - descriptor_addr] = NON_ZERO

        log(f"FORWARD NEW: {descriptor_addr:#x} --> {forward_description}")

        # Step 4
        for base_addr in ptr_to_base_addr[descriptor_addr]:
            # This is the base address, we can use to get the original descriptions
            # Compare forware
            if base_addr not in lli_cands:
                lli_cands[base_addr] = dict()   
            match_forward_description = descriptions[base_addr][FORWARD]
            match_backward_description = descriptions[base_addr][BACKWARD]
            log(f"Comparing with {base_addr:#x}: {match_forward_description}")

            matches = 0
            max_score = 0
            ptr_null_matches = 0

            # TODO maybe comparison into individual functions????
            # TODO dont count all maches equally? pointer matches > nonzero matches?
            if (match_forward_description.keys() == forward_description.keys()):
                for offset in match_forward_description:
                    #log(f"offset {offset:#x}: {description[offset]} ?= {match_description[offset]}")
                    max_score += 1
                    if match_forward_description[offset] == forward_description[offset]:

                        if match_forward_description[offset] == NON_ZERO:
                            matches -= 0.5
                        matches += 1
                        continue # got a match nice
                    if match_forward_description[offset] == POINTER and forward_description[offset] == NULL:
                        ptr_null_matches += 1
                        lli_cands[base_addr][descriptor_addr] = offset
                        #description[offset] = LLI_PTR
                        continue # potential linked list pointer match
            
            fw_matches = 0
            if matches:
                fw_matches = (matches + ptr_null_matches) / max_score
                log("COMPARING")
                log(match_forward_description)
                log(forward_description)
                log(fw_matches)
                log(matches)
                log(max_score)
                log("==========================")

            matches = 0
            max_score = 0
            ptr_null_matches = 0
            if match_backward_description.keys() == backward_description.keys():
                for offset in match_backward_description:
                    max_score += 1
                    #log(f"offset {offset:#x}: {description[offset]} ?= {match_description[offset]}")
                    if match_backward_description[offset] == backward_description[offset]:
                        if match_backward_description[offset] == NON_ZERO:
                            max_score -= 1
                        matches += 1
                        continue # got a match nice
                    if match_backward_description[offset] == POINTER and backward_description[offset] == NULL:
                        ptr_null_matches += 1
                        lli_cands[base_addr][descriptor_addr] = offset
                        #description[offset] = LLI_PTR
                        continue # potential linked list pointer match

            bw_matches = 0
            if matches:
                bw_matches = (matches + ptr_null_matches) / max_score

            if base_addr not in match_scores:
                match_scores[base_addr] = {descriptor_addr: {FORWARD: fw_matches, BACKWARD: bw_matches}}
            else:
                match_scores[base_addr][descriptor_addr] = {FORWARD: fw_matches, BACKWARD: bw_matches}

    # Step 5
    # TODO some sanity checking, so descriptors wont overlap
    winners = dict()
    log(match_scores)
    sorted_scores = sorted([(base,direction,ptr,score) for base, field in match_scores.items() for ptr, res in field.items() for direction, score in res.items()], key=lambda x: x[3], reverse=True)
    log(sorted_scores)
    if not sorted_scores:
        highest_score = HIGHSCORE_NOT_AVAILABLE
    else:
        highest_score = sorted_scores[0][3]

    winners = dict([(base, direction) for base,direction,ptr,score in sorted_scores if score == highest_score])
    lli_cands = dict([(base, lli_cands[base][ptr]) for base,direction,ptr,score in sorted_scores if score == highest_score and base in lli_cands and ptr in lli_cands[base]])

    log('+++++++++++++++++++++++++++')
    return winners, lli_cands, highest_score