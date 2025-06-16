from datetime import timedelta

from dataclasses import dataclass

@dataclass
class DMAJobPerfResult:
    ram_trace_size: int
    mmio_trace_size: int
    seconds_trace_gen: float
    seconds_snippet_gen: float

@dataclass
class DMAJobPerfSummary:
    ram_trace_size_max: int = 0
    ram_trace_size_avg: int = 0
    time_trace_gen: float = 0.0
    time_dma_snippet_gen: float = 0.0
    max_time_trace_gen: float = 0.0
    max_dma_snippet_gen: float = 0.0
    avg_time_trace_gen: float = 0.0
    avg_dma_snippet_gen: float = 0.0
    max_factor_trace_gen_to_dma_snip_gen: float = 0.0
    path_max_factor_trace_gen_to_dma_snip_gen: str = "<UNKNOWN>"
