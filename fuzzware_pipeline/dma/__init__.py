from fuzzware_harness.util import load_config_deep

def is_dma_config_update(current_path, candidate_path):
    current_contents = load_config_deep(current_path)
    candidate_contents = load_config_deep(candidate_path)

    return candidate_contents != current_contents
