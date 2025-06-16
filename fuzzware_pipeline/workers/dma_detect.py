from ..util.eval_utils import dump_dma_perf_metadata
from ..util.config import save_config, load_extra_args
from .. import naming_conventions as nc
from ..dma.dma_script import eval_dma
from ..dma import dma_script
from ..dma.eval_script import eval_votes
from .tracegen import TraceGenerator
from ..dma.perf_meta import DMAJobPerfResult

from fuzzware_harness.util import load_config_deep

import datetime
import os
import logging
import rq
import subprocess
import sys
from multiprocessing import Pool
from pathlib import Path
from rq.worker import WorkerStatus
from tqdm import tqdm
from typing import Tuple, List

from ..logging_handler import logging_handler
logger = logging_handler().get_logger("DMA")

from cProfile import Profile
from pstats import SortKey, Stats

DIR = os.path.dirname(os.path.realpath(__file__))
RUST_DMA_DETECT_BINARY_PATH = os.path.join(DIR, "..", "..", "dma_modeling", "target", "release", "detect_dma")

def call_rust_dma_modeling(config_path, out_file_path, ram_trace_path, mmio_trace_path, snip_format, quiet=False):
    full_args = [RUST_DMA_DETECT_BINARY_PATH, "model", "--fuzzware-config", config_path, "-o", out_file_path, "--fuzzware-ram-trace", ram_trace_path, "--fuzzware-mmio-trace", mmio_trace_path, "--snip-format", snip_format]
    if quiet:
        subprocess.check_call(full_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    else:
        env = {**os.environ, "RUST_LOG": "info" }
        subprocess.check_call(full_args, env=env)

def call_rust_dma_snippet_summary(config_path, snipdir_path, out_file_path, snip_format, quiet=False):
    full_args = [RUST_DMA_DETECT_BINARY_PATH, "summarize", "-o", out_file_path, "--snipdir", snipdir_path, "--snip-format", snip_format]
    if quiet:
        subprocess.check_call(full_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    else:
        env = {**os.environ, "RUST_LOG": "info" }
        subprocess.check_call(full_args, env=env)

def call_python_dma_modeling(config_map, out_file_path, ram_trace_path, mmio_trace_path, quiet=False, debug=False):
    with Profile() as profile:
        if debug:
            dma_script.set_log(1)
        res, _, _ = eval_dma(config_map, ram_trace_path, mmio_trace_path, None)
        if debug:
            dma_script.set_log(0)
        if not quiet:
            (
                Stats(profile)
                .strip_dirs()
                .sort_stats(SortKey.TIME)
                .print_stats(15)
            )

    # Only save in case we have an actual result
    if res:
        save_config(res, out_file_path)

def gen_dma_snippet_single(config_path, config_map, out_file_path, ram_trace_path, mmio_trace_path, snip_format, use_python_version=False, quiet=True, debug=False):
    assert ram_trace_path is not None and mmio_trace_path is not None
    trace_paths = (ram_trace_path, mmio_trace_path)

    if debug:
        quiet = False

    for p in trace_paths:
        if not os.path.exists(p):
            ERROR_MSG = f"Trace path required for DMA snippet generation does not exist: {p}"
            logger.error(ERROR_MSG)
            raise ValueError(ERROR_MSG)

    if use_python_version:
        assert snip_format == "yaml"
        if config_map is None:
            config_map = load_config_deep(config_path)
        call_python_dma_modeling(config_map, out_file_path, ram_trace_path, mmio_trace_path, quiet=quiet, debug=debug)
    else:
        call_rust_dma_modeling(config_path, out_file_path, ram_trace_path, mmio_trace_path, snip_format, quiet=quiet)

    sys.stdout.flush()
    sys.stderr.flush()

    for p in trace_paths:
        os.remove(p)

    if not quiet:
        if os.path.exists(out_file_path):
            logger.info("DMA modeling created a DMA snippet.")
        else:
            logger.info("No DMA snippet...")

def evaluate_dma_snippets(config_path, dma_snippet_dir_path, out_file_path, snip_format, use_python_version=False, silent=False):
    logger.info("Evaluating DMA snippets")

    if use_python_version:
        assert snip_format == "yaml"
        with Profile() as profile:
            res = eval_votes(dma_snippet_dir_path)
            if not silent:
                (
                    Stats(profile)
                    .strip_dirs()
                    .sort_stats(SortKey.TIME)
                    .print_stats(15)
                )
        # Only save in case we have an actual result
        if res:
            save_config(res, out_file_path)
    else:
        call_rust_dma_snippet_summary(config_path, dma_snippet_dir_path, out_file_path, snip_format, silent)

class DMASnippetGenerator:
    trace_gen: TraceGenerator = None
    quiet: bool = False

    last_config_path = None
    config_map: dict = {}

    def __init__(self, quiet=True, debug=False):
        self.trace_gen = TraceGenerator(silent=quiet)
        self.quiet = quiet
        self.debug = debug

    def gen_dma_snippet(self, config_path, extra_args, input_path, out_file_path, snip_format, use_python_version) -> Tuple[str, DMAJobPerfResult]:
        """ Generate a DMA snippet for a given input path and return trace size and generation time metadata

        Returns (out_file_path, perf_meta)
        """
        if config_path != self.last_config_path:
            logger.debug(f"Loading new config: {config_path} (old: {self.last_config_path})")
            self.last_config_path = config_path
            if use_python_version:
                self.config_map = load_config_deep(config_path)

        time_before_trace_gen = datetime.datetime.now(datetime.timezone.utc)
        self.trace_gen.gen_temp_trace(config_path, extra_args,
                        input_path, gen_ram_trace=True, gen_mmio_trace=True)
        time_end_trace_gen = datetime.datetime.now(datetime.timezone.utc)

        ram_trace_path = str(self.trace_gen.trace_proc.stable_ramtrace_path)
        mmio_trace_path = str(self.trace_gen.trace_proc.stable_mmiotrace_path)
        ram_trace_size = os.stat(ram_trace_path).st_size
        mmio_trace_size = os.stat(mmio_trace_path).st_size

        gen_dma_snippet_single(config_path, self.config_map, out_file_path,
                        ram_trace_path, mmio_trace_path,
                        snip_format=snip_format,
                        use_python_version=use_python_version, quiet=self.quiet,
                        debug=self.debug
        )
        time_end_snippet_gen = datetime.datetime.now(datetime.timezone.utc)
        seconds_trace_gen = (time_end_trace_gen - time_before_trace_gen).total_seconds()
        seconds_snippet_gen = (time_end_snippet_gen - time_end_trace_gen).total_seconds()

        perf_data = DMAJobPerfResult(ram_trace_size, mmio_trace_size, seconds_trace_gen, seconds_snippet_gen)

        return out_file_path, perf_data

    def __del__(self):
        if self.trace_gen:
            self.trace_gen.__del__()
        try:
            super().__del__()
        except AttributeError:
            pass

class DMADetectWorker(rq.Worker):
    dma_gen: DMASnippetGenerator = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dma_gen = DMASnippetGenerator(quiet=True)

    def execute_job(self, job, queue): #pylint: disable=inconsistent-return-statements
        logger.info(job)

        if queue.name != nc.REDIS_QUEUE_NAME_DMA_GEN_SNIPPET:
            assert queue.name == nc.REDIS_QUEUE_NAME_DMA_MODELING
            # For snippet summary evaluation, forward to original implementation
            return super().execute_job(job, queue)

        config_path, extra_args, input_path, out_file_path, snip_format, use_python_version = job.args
        logger.info(f"Detecting DMA in input {input_path}")

        self.prepare_job_execution(job)
        job.started_at = datetime.datetime.now(datetime.timezone.utc)

        out_path, perf_meta = self.dma_gen.gen_dma_snippet(config_path, extra_args, input_path, out_file_path, snip_format, use_python_version)

        job.ended_at = datetime.datetime.now(datetime.timezone.utc)
        logger.info(f"Generated on-demand traces in {round(perf_meta.seconds_trace_gen * 1000, 2)} ms, dma snippet in {round(perf_meta.seconds_snippet_gen * 1000, 2)} ms, job total: {round((job.ended_at-job.started_at).total_seconds(), 3)} sec. Size(ram trace): {round(perf_meta.ram_trace_size/(1024*1024), 2)}MB, Size(mmio trace): {round(perf_meta.mmio_trace_size/(1024*1024), 2)}MB")

        job.set_status(rq.job.JobStatus.FINISHED)
        job._result = (out_path, perf_meta)

        self.handle_job_success(job=job, queue=queue,
            started_job_registry=queue.started_job_registry)

        self.set_state(WorkerStatus.IDLE)

def pool_func_init_gen_proc(quiet, debug):
    global snip_gen
    snip_gen = DMASnippetGenerator(quiet=quiet, debug=debug)

def pool_func_gen_dma_snippet(job) -> Tuple[str, int, int, float, float]:
    global snip_gen

    return snip_gen.gen_dma_snippet(*job)

def batch_gen_dma_snippets(projdir, snip_format, snipdir_postfix="", log_progress=False, num_procs=1, force_overwrite=False, use_python_version=False, use_python_summary=False, quiet=True, debug=False) -> List[Tuple[str, DMAJobPerfResult]]:
    """ Run DMA snippet generation for a project directory

    Returns list of results from DMASnippetGenerator.gen_dma_snippet:
        [(out_file_path_1, perf_result_1), ]
    """
    if quiet:
        logger.logger.setLevel(logging.ERROR)
        logging_handler().get_logger("tracegen").logger.setLevel(logging.ERROR)
    snippet_dir = nc.dma_snippet_path_for_proj(projdir, snipdir_postfix)
    if not os.path.exists(snippet_dir):
        os.mkdir(snippet_dir)
    out_model_dir = os.path.join(snippet_dir, nc.SESS_DIRNAME_DMA_CFG_CANDIDATES)
    if not os.path.exists(out_model_dir):
        os.mkdir(out_model_dir)

    jobs = []
    for main_dir in nc.main_dirs_for_proj(projdir):
        config_path = nc.config_file_for_main_path(main_dir)
        extra_args = load_extra_args(nc.extra_args_for_config_path(config_path))

        for input_path in nc.input_paths_for_main_dir(main_dir):
            input_path = str(input_path)
            snippet_out_path = nc.dma_snippet_path_for_input_path(input_path, proj_dir_path=projdir, out_snippet_dir_suffix=snipdir_postfix)
            if force_overwrite or not os.path.exists(snippet_out_path):
                jobs.append([config_path, extra_args, input_path, snippet_out_path, snip_format, use_python_version])

    pool_init_func, pool_worker_func = pool_func_init_gen_proc, pool_func_gen_dma_snippet
    pool_init_args = [ quiet, debug ]

    dma_job_perf_out_path = os.path.join(out_model_dir, nc.PIPELINE_FILENAME_DMA_MODEL_PERF_METADATA)
    if jobs and os.path.exists(dma_job_perf_out_path):
        os.remove(dma_job_perf_out_path)

    results: List[Tuple[str, DMAJobPerfResult]] = []
    with Pool(num_procs, pool_init_func, pool_init_args) as p:
        it = p.imap(pool_worker_func, jobs)
        if log_progress and len(jobs) / num_procs > 50:
            it = tqdm(it, total=len(jobs))
        for res in it:
            results.append(res)

    time_vote_eval_start = datetime.datetime.now(datetime.timezone.utc)
    dma_model_out_path = os.path.join(out_model_dir, nc.PIPELINE_FILENAME_DMA_CFG)
    if os.path.exists(dma_model_out_path):
        os.remove(dma_model_out_path)
    evaluate_dma_snippets(None, snippet_dir, dma_model_out_path, snip_format, silent=quiet, use_python_version=use_python_summary)
    time_vote_eval_end = datetime.datetime.now(datetime.timezone.utc)
    time_vote_eval = (time_vote_eval_end - time_vote_eval_start).total_seconds()

    if results:
        ram_trace_size_max = max([perf_data.ram_trace_size for _, perf_data in results])
        ram_trace_size_avg = sum([perf_data.ram_trace_size for _, perf_data in results]) / len(results)

        time_trace_gen = sum((perf_data.seconds_trace_gen for _, perf_data in results))
        time_dma_snippet_gen = sum((perf_data.seconds_snippet_gen for _, perf_data in results))
        print(f"RAM trace sizes (max, average)                  : {round(ram_trace_size_max / (1024*1024), 2)}MB, {round(ram_trace_size_avg / (1024*1024), 2)}MB")
        print(f"Total CPU time taken for trace generation       : {round(time_trace_gen, 3)}s")
        print(f"Total CPU time taken for DMA snippet generation : {round(time_dma_snippet_gen, 3)}s")
    else:
        print("No snippets needed to be evaluated")
    print(f"Total time taken for DMA vote evalulation       : {round(time_vote_eval, 3)}s")

    if results:
        print(f"\nWriting stats to {dma_job_perf_out_path}")
        dump_dma_perf_metadata(dma_job_perf_out_path, results)

    return results
