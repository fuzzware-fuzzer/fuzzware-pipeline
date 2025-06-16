#!/usr/bin/env python3
import os
from os import listdir
from os.path import isfile, join
#from .eval_utils import *
# from diff_script import diff
from fuzzware_harness.util import load_config_deep
from .dma_util import RESULT_SG, RESULT_ACCESS, RESULT_CONFIG, RESULT_DESCRIPTOR, RESULT_EVENT, RESULT_SIZE_MAX, RESULT_SIZE_MIN, RESULT_MMIO, MMIO_DMA, SG_DMA
SG_DMA = 'sg'

DEFAULT_PACKET_LIMIT = 5
LL_TYPE = "ll_typedef"
GENERIC_DMA_CONTROLLER = "fuzzware_harness.peripherals.generic_dma.GenericDMAC"
POINTER_TYPE = "pointer"
BUFFER_TYPE = "buffer"
VOTES = "votes"
BUF_KEY = "buf"
MMIO_REGISTER = "mmio_register"
BUF_ADDRESS = "address"

# Keys for the dma config
PERIPH = "my_dma_periph"
CLASS = "class"
PACKET_LIMIT = "packet_limit"
DESCRIPTORS = "descriptors"
OFFSET = "offset"
TYPE = "type"
TO = "to"
MIN_SIZE = "min"
MAX_SIZE = "max"

VALID_MODEL_TYPES = (
    MMIO_DMA,
    SG_DMA
)

############################################
### EVAL STORED SCRIPT RESULTS #############
############################################
def extract_results_from_snippets(snippet_dir: str) -> dict:
    files = [f"{snippet_dir}/{f}" for f in listdir(snippet_dir) if isfile(join(snippet_dir, f))]
    vote_dict = dict()
    for file in files:
        snippet = load_config_deep(file)
        for dma_type, entry in snippet.items():
            if dma_type not in VALID_MODEL_TYPES:
                continue
            for buf_addr, field in entry.items():
                if buf_addr in vote_dict and dma_type in vote_dict[buf_addr]:
                    vote_info = vote_dict[buf_addr][dma_type]
                    if vote_info[MMIO_REGISTER] == -1:
                        #if the mmio register has not been set, update it
                        vote_info[MMIO_REGISTER] = field[RESULT_MMIO]

                    if field[RESULT_SIZE_MIN] > vote_info[RESULT_SIZE_MIN]:
                        vote_info[RESULT_SIZE_MIN] = field[RESULT_SIZE_MIN]
                        if not (vote_info[RESULT_SIZE_MAX] > field[RESULT_SIZE_MIN]):
                            vote_info[RESULT_SIZE_MAX] = field[RESULT_SIZE_MAX] if field[RESULT_SIZE_MAX] > field[RESULT_SIZE_MIN] else field[RESULT_SIZE_MIN]
                            
                    vote_info[VOTES] = vote_info[VOTES] + 1

                    if field[RESULT_SG] and field[RESULT_SG] != vote_dict[buf_addr][dma_type][RESULT_SG] and field[RESULT_MMIO] != -1:
                        # TODO voting for different scatter gather
                        if vote_dict[buf_addr][dma_type][RESULT_SG] == 0:
                            vote_dict[buf_addr][dma_type][RESULT_SG] = field[RESULT_SG]
                            vote_dict[buf_addr][dma_type][RESULT_DESCRIPTOR] = field[RESULT_DESCRIPTOR]
                        else:
                            # TODO
                            if field[RESULT_MMIO] and field[RESULT_MMIO] == vote_dict[buf_addr][dma_type][MMIO_REGISTER] and field[RESULT_MMIO] != -1:
                                print(f"TODO {field[RESULT_SG]:#x} : {vote_dict[buf_addr][dma_type][RESULT_SG]:#x}")

                            else:
                                print(f"ERROR {field[RESULT_SG]:#x} : {vote_dict[buf_addr][dma_type][RESULT_SG]:#x}")
                else:
                    # TODO is_sg is set to False. We need to store information on that in the snippets to reconstruct this
                    new_vote_dict_entry(vote_dict, field, file, buf_addr, dma_type)

    return vote_dict

def new_vote_dict_entry(vote_dict: dict, field: dict, file: str, buf_addr: int, dma_type: str):
    if buf_addr not in vote_dict:
        vote_dict[buf_addr] = dict()
    
    vote_dict[buf_addr][dma_type] = {VOTES: 1, 
                        RESULT_SIZE_MIN: field[RESULT_SIZE_MIN],
                        RESULT_SIZE_MAX: field[RESULT_SIZE_MAX] if field[RESULT_SIZE_MAX] > field[RESULT_SIZE_MIN] else field[RESULT_SIZE_MIN], 
                        'path': file, 
                        RESULT_SG: field[RESULT_SG],
                        MMIO_REGISTER: field[RESULT_MMIO], 
                        RESULT_CONFIG: field[RESULT_CONFIG], 
                        RESULT_ACCESS: field[RESULT_ACCESS]}

    print(f"New vote entry: ({field[RESULT_MMIO]:#x}, {buf_addr:#x}) : {'scatter-gather' if vote_dict[buf_addr][dma_type][RESULT_SG] else 'buffer'}")

    if vote_dict[buf_addr][dma_type][RESULT_SG]:
        vote_dict[buf_addr][dma_type][RESULT_DESCRIPTOR] = field[RESULT_DESCRIPTOR]
    return

def eval_votes(snippet_dir: str, silent=False) -> dict:
    """
    Given a dma snippet directory eval all snippets and give out a peripheral configuratio
    Args:
        vote_dir (str): 
    Returns:
        dict():
    """
    # Step 1:  Evaluate all dma snippets and sort them ito a vote dictionary
    vote_dict = extract_results_from_snippets(snippet_dir)
    if not vote_dict:
        return {}
    #print(vote_dict)
    sorted_mmio_votes = iter([None])
    sorted_sg_votes = iter([None])
    mmio_votes = dict([(buf_addr, field) for buf_addr, direction_entry in vote_dict.items() for direction, field in direction_entry.items() if direction == MMIO_DMA])
    sg_votes = dict([(buf_addr, field) for buf_addr, direction_entry in vote_dict.items() for direction, field in direction_entry.items() if direction == SG_DMA])

    if mmio_votes:
        sorted_mmio_votes = iter(dict(sorted(mmio_votes.items(), key=lambda item: item[1][VOTES], reverse=True)))   
    if sg_votes:
        sorted_sg_votes = iter(dict(sorted(sg_votes.items(), key=lambda item: item[1][VOTES], reverse=True)))   
    
    # Step 2: Get the buffer with the highest amount of votes
    top_mmio_buf = next(sorted_mmio_votes)
    top_sg_buf = next(sorted_sg_votes)
    top_direction = ''
    double_use = False
    if top_mmio_buf and top_sg_buf:
        if top_mmio_buf == top_sg_buf:
            # NXP pattern, where buffer is loaded from descriptor to mmio by the firmware, but also present in descriptor
            double_use = True
            top_buf = top_mmio_buf
        else:
            if vote_dict[top_mmio_buf][MMIO_DMA][VOTES] > vote_dict[top_sg_buf][SG_DMA][VOTES]:
                top_buf = top_mmio_buf
                top_direction = MMIO_DMA
                sorted_votes = sorted_mmio_votes
            else:
                top_buf = top_sg_buf
                top_direction = SG_DMA
                sorted_votes = sorted_sg_votes
    elif top_mmio_buf and not top_sg_buf:
        top_buf = top_mmio_buf
        top_direction = MMIO_DMA
        sorted_votes = sorted_mmio_votes
    elif not top_mmio_buf and top_sg_buf:
        top_buf = top_sg_buf
        top_direction = SG_DMA
        sorted_votes = sorted_sg_votes
    else:
        # no decisive winner
        return {}


    # Step 3: Place the results in a config
    if not double_use:
        # Regular pattern, i.e., either only SG or only MMIO
        # Get the best buffer
        first_buf = f"{BUF_KEY}_1"
        top_bufs = {first_buf: {**vote_dict[top_buf][top_direction], BUF_ADDRESS: top_buf}}

        # If votes are below threshold, discard it
        vote_threshold = 2
        top_buf_votes = top_bufs[first_buf][VOTES]
        if top_buf_votes < vote_threshold:
            return {}

        if top_bufs[first_buf][RESULT_SG] == 0:
            # CASE 1 flat case without scatter-gather
            #check if other candidates have the same amount of votes
            for next_res in sorted_votes:
                if vote_dict[next_res][top_direction][VOTES] == top_bufs[first_buf][VOTES]:
                    top_bufs[f"{BUF_KEY}_{len(top_bufs) + 1}"] = {BUF_ADDRESS: next_res, **vote_dict[next_res][top_direction]}
            # CASE 1 flat case without scatter-gather
            result = {PERIPH : {
                        CLASS: GENERIC_DMA_CONTROLLER,
                        PACKET_LIMIT: DEFAULT_PACKET_LIMIT,
                        "known_sizes": {top_bufs[first_buf][BUF_ADDRESS]: {MIN_SIZE: top_bufs[first_buf][RESULT_SIZE_MIN],
                                                                            MAX_SIZE: top_bufs[first_buf][RESULT_SIZE_MAX]
                                    }
                        },
                        DESCRIPTORS: [{"addr": top_bufs[first_buf][MMIO_REGISTER],
                                        "known_values": [top_bufs[first_buf][BUF_ADDRESS]],
                                        TO: {TYPE: BUFFER_TYPE}}]
            }}

        else:
            # CASE 2 Scatter gather
            result = {PERIPH : {
                        CLASS: GENERIC_DMA_CONTROLLER,
                        PACKET_LIMIT: DEFAULT_PACKET_LIMIT,
                        "known_sizes": dict(),
                        DESCRIPTORS: list()
            }}

            # descriptors
            desc_offset = 0
            result[PERIPH][DESCRIPTORS].append({"addr": top_bufs[first_buf][MMIO_REGISTER], 
                                                        TO: {"typedef": LL_TYPE,
                                                                "fields": list()
                                                        }})
            
            for offset, desc_type in top_bufs[first_buf][RESULT_DESCRIPTOR].items():
                if desc_type != POINTER_TYPE and desc_type != "linked_list_pointer":
                    # TODO so far only pointer
                    continue

                if desc_type == POINTER_TYPE:
                    result[PERIPH][DESCRIPTORS][desc_offset][TO]["fields"].append({OFFSET: offset,
                                                                                            TYPE: desc_type,
                                                                                            TO: { TYPE: BUFFER_TYPE
                                                                                            }})
                elif desc_type == "linked_list_pointer":
                    result[PERIPH][DESCRIPTORS][desc_offset][TO]["fields"].append({OFFSET: offset,
                                                                                            TYPE: POINTER_TYPE,
                                                                                            TO: { TYPE: LL_TYPE
                                                                                            }})

            # known vals; always add top buf
            result[PERIPH]["known_sizes"][top_bufs[first_buf][BUF_ADDRESS]] ={MIN_SIZE: top_bufs[first_buf][RESULT_SIZE_MIN],
                                                                            MAX_SIZE: top_bufs[first_buf][RESULT_SIZE_MAX]
                                                                        }
            # Now check all other vote dict entries if we have an entry with the same descriptor and add it to the known sizes
            for buf_addr in sorted_votes:
                if vote_dict[buf_addr][top_direction][MMIO_REGISTER] == result[PERIPH][DESCRIPTORS][0]["addr"] and vote_dict[buf_addr][top_direction][RESULT_SG] ==  top_bufs[first_buf][RESULT_SG]:
                    result[PERIPH]["known_sizes"][buf_addr] ={MIN_SIZE: vote_dict[buf_addr][top_direction][RESULT_SIZE_MIN],
                                                                                            MAX_SIZE: vote_dict[buf_addr][top_direction][RESULT_SIZE_MAX]
                                                                                            }   
    if double_use:
        # check if multiple
        descriptor = list()
        for offset, desc_type in vote_dict[top_buf][SG_DMA][RESULT_DESCRIPTOR].items():
            if desc_type != POINTER_TYPE and desc_type != "linked_list_pointer":
                # TODO so far only pointer
                continue

            if desc_type == POINTER_TYPE:
                descriptor.append({OFFSET: offset,
                                    TYPE: desc_type,
                                    TO: { TYPE: BUFFER_TYPE
                                    }})
            elif desc_type == "linked_list_pointer":
                descriptor.append({OFFSET: offset,
                                    TYPE: POINTER_TYPE,
                                    TO: { TYPE: LL_TYPE
                                    }})

        # check if there are further dma buffers that have the same descriptor
        known_sizes = {top_buf: {MIN_SIZE: vote_dict[top_buf][SG_DMA][RESULT_SIZE_MIN],
                                MAX_SIZE: vote_dict[top_buf][SG_DMA][RESULT_SIZE_MAX]}}
        for next_res in sorted_sg_votes:
            if vote_dict[next_res][SG_DMA][RESULT_SG] == vote_dict[top_buf][SG_DMA][RESULT_SG]:
                known_sizes[next_res] = {MIN_SIZE: vote_dict[next_res][SG_DMA][RESULT_SIZE_MIN],
                                        MAX_SIZE: vote_dict[next_res][SG_DMA][RESULT_SIZE_MAX]}

        # Double use pattern
        result = {PERIPH : {
                        CLASS: GENERIC_DMA_CONTROLLER,
                        PACKET_LIMIT: DEFAULT_PACKET_LIMIT,
                        "known_sizes": known_sizes,
                        DESCRIPTORS: [{"addr": vote_dict[top_buf][MMIO_DMA][MMIO_REGISTER],
                                        "known_values": [top_buf],
                                        TO: {TYPE: BUFFER_TYPE}},
                                        {"addr": vote_dict[top_buf][SG_DMA][MMIO_REGISTER],
                                         TO: {
                                             "typedef": LL_TYPE,
                                             "fields": descriptor
                                         }}
                                        ]
            }}


                                    
    # Prepare the return dict        
    peripherals = {'peripherals': result}
    return peripherals

