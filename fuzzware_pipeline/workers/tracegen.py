import copy
import datetime
import math
import os
import subprocess
import uuid
from pathlib import Path
from multiprocessing import Pool
from tqdm import tqdm

import rq
from fuzzware_pipeline.logging_handler import logging_handler
from rq.worker import WorkerStatus

from .. import naming_conventions as nc
from ..run_target import gen_run_arglist, run_target
from ..util.config import load_extra_args, parse_extra_args

logger = logging_handler().get_logger("tracegen")

FORKSRV_FD = 198

# Make sure these names are synchronized with the argument names below
ARGNAME_BBL_SET_PATH, ARGNAME_MMIO_SET_PATH, ARGNAME_BBL_HASH_PATH = "bbl_set_path", "mmio_set_path", "bbl_hash_path"
ARGNAME_BBL_TRACE_PATH, ARGNAME_RAM_TRACE_PATH, ARGNAME_MMIO_TRACE_PATH = "bbl_trace_path", "ram_trace_path", "mmio_trace_path"
ARGNAME_INTERRUPT_TRACE_PATH = "interrupt_trace_path"
ARGNAME_DMA_TRACE_PATH = "dma_trace_path"
ARGNAME_EXTRA_ARGS = "extra_args"
FORKSERVER_UNSUPPORTED_TRACE_ARGS = ("dma_trace_path", )
def gen_traces(config_path, input_path, bbl_trace_path=None, ram_trace_path=None, mmio_trace_path=None, bbl_set_path=None, mmio_set_path=None, extra_args=None, silent=False, bbl_hash_path=None, interrupt_trace_path=None, dma_trace_path=None):
    extra_args = list(extra_args) if extra_args else []

    if bbl_trace_path is not None:
        extra_args += ["--bb-trace-out", bbl_trace_path]
    if ram_trace_path is not None:
        extra_args += ["--ram-trace-out", ram_trace_path]
    if mmio_trace_path is not None:
        extra_args += ["--mmio-trace-out", mmio_trace_path]
    if bbl_set_path is not None:
        extra_args += ["--bb-set-out", bbl_set_path]
    if mmio_set_path is not None:
        extra_args += ["--mmio-set-out", mmio_set_path]
    if bbl_hash_path is not None:
        extra_args += ["--bb-hash-out", bbl_hash_path]
    if interrupt_trace_path is not None:
        extra_args += ["--interrupt-trace-out", interrupt_trace_path]
    if dma_trace_path is not None:
        extra_args += ["--dma-trace-out", dma_trace_path]

    run_target(config_path, input_path, extra_args, silent=silent, stdout=subprocess.DEVNULL if silent else None, stderr=subprocess.DEVNULL if silent else None)
    return True

def gen_missing_maindir_traces(maindir, required_trace_prefixes, fuzzer_nums=None, tracedir_postfix="", log_progress=False, verbose=False, crashing_inputs=False, force_overwrite=False, num_emulators=1, force_process_per_input=False, force_slow_tracing=False):
    projdir = nc.project_base(maindir)
    config_path = nc.config_file_for_main_path(maindir)
    extra_args = parse_extra_args(load_extra_args(nc.extra_args_for_config_path(config_path)), projdir)

    if force_slow_tracing:
        extra_args.append("--force-slow-tracing")

    trace_jobs = []
    fuzzer_dirs = nc.fuzzer_dirs_for_main_dir(maindir)

    if fuzzer_nums is not None:
        assert all(0 < i <= len(fuzzer_dirs) for i in fuzzer_nums)
        fuzzer_dirs = [fuzzer_dirs[i-1] for i in fuzzer_nums]

    can_use_forkserver = False
    if not force_process_per_input and not force_slow_tracing:
        can_use_forkserver = all(prefix in nc.NATIVE_TRACE_FILENAME_PREFIXES for prefix in required_trace_prefixes)

    need_bb_set, need_mmio_set, need_bb_hash = False, False, False
    need_bb_trace, need_ram_trace, need_mmio_trace = False, False, False
    need_interrupt_trace = False
    need_dma_trace = False

    for fuzzer_dir in fuzzer_dirs:
        tracedir = fuzzer_dir.joinpath(nc.trace_dirname(tracedir_postfix, is_crash=crashing_inputs))

        # In case we have a custom tracedir postfix, we need to create directories on demand
        if not tracedir.exists():
            tracedir.mkdir()
        elif force_overwrite == True:
            # Assumption: Only files, no directories, in tracedir
            for trace in tracedir.iterdir():
                trace.unlink()

        for input_path in nc.input_paths_for_fuzzer_dir(fuzzer_dir, crashes=crashing_inputs):
            bbl_trace_path, ram_trace_path, mmio_trace_path = None, None, None
            bbl_set_path, mmio_set_path, bbl_hash_path = None, None, None
            interrupt_trace_path = None
            dma_trace_path = None
            for trace_path in nc.trace_paths_for_input(input_path):
                trace_dir, trace_name = os.path.split(trace_path)

                if tracedir_postfix:
                    trace_path = os.path.join(trace_dir+f"_{tracedir_postfix}", trace_name)

                for prefix in required_trace_prefixes:
                    if trace_name.startswith(prefix) and not os.path.exists(trace_path):
                        if prefix == nc.PREFIX_BASIC_BLOCK_TRACE:
                            bbl_trace_path = trace_path
                            need_bb_trace = True
                        elif prefix == nc.PREFIX_MMIO_TRACE:
                            mmio_trace_path = trace_path
                            need_mmio_trace = True
                        elif prefix == nc.PREFIX_RAM_TRACE:
                            ram_trace_path = trace_path
                            need_ram_trace = True
                        elif prefix == nc.PREFIX_BASIC_BLOCK_SET:
                            bbl_set_path = trace_path
                            need_bb_set = True
                        elif prefix == nc.PREFIX_MMIO_SET:
                            mmio_set_path = trace_path
                            need_mmio_set = True
                        elif prefix == nc.PREFIX_BASIC_BLOCK_HASH:
                            bbl_hash_path = trace_path
                            need_bb_hash = True
                        elif prefix == nc.PREFIX_INTERRUPT_TRACE:
                            interrupt_trace_path = trace_path
                            need_interrupt_trace = True
                        elif prefix == nc.PREFIX_DMA_TRACE:
                            dma_trace_path = trace_path
                            need_dma_trace = True
                        else:
                            assert False
                        break

            if any(p is not None for p in (bbl_trace_path, ram_trace_path, mmio_trace_path, bbl_set_path, mmio_set_path, bbl_hash_path, interrupt_trace_path, dma_trace_path)):
                trace_jobs.append((str(input_path), bbl_trace_path, ram_trace_path, mmio_trace_path, bbl_set_path, mmio_set_path, bbl_hash_path, interrupt_trace_path, dma_trace_path))

    # If we found jobs for the given config path, add them
    if not trace_jobs:
        if log_progress:
            logger.info("No traces to generate for main path")
        return 0

    if can_use_forkserver:
        pool_init_func, pool_worker_func = pool_init_forkserver_worker, pool_func_gen_traces_forkserver
        pool_init_args = verbose, str(config_path), extra_args, need_bb_set, need_mmio_set, need_bb_hash, need_bb_trace, need_ram_trace, need_mmio_trace, need_interrupt_trace, dma_trace_path
    else:
        pool_init_func, pool_worker_func = pool_init_non_native, pool_func_gen_traces_new_proc
        pool_init_args = verbose, str(config_path), extra_args

    with Pool(num_emulators, pool_init_func, pool_init_args) as p:
        it = p.imap(pool_worker_func, trace_jobs)
        if log_progress and len(trace_jobs) / num_emulators > 50:
            maindir_no, _ = nc.main_and_fuzzer_number(maindir)
            it = tqdm(it, total=len(trace_jobs), desc=f"Main {maindir_no:3d}")
        for _ in it:
            pass

    return len(trace_jobs)

def pool_init_non_native(verbose, config_path, extra_args):
    global pool_arg_verbose, pool_arg_config_path, pool_arg_extra_args
    pool_arg_verbose, pool_arg_config_path, pool_arg_extra_args = verbose, config_path, extra_args

def pool_init_forkserver_worker(verbose, config_path, extra_args, gen_bb_set, gen_mmio_set, gen_bb_hash, gen_bb_trace, gen_ram_trace, gen_mmio_trace, gen_interrupt_trace, gen_dma_trace):
    global pool_state_gentrace_proc
    pool_state_gentrace_proc = TraceGenProc(config_path, extra_args, gen_bb_set=gen_bb_set, gen_mmio_set=gen_mmio_set, gen_bb_hash=gen_bb_hash,
                                        gen_bb_trace=gen_bb_trace, gen_ram_trace=gen_ram_trace, gen_mmio_trace=gen_mmio_trace, gen_interrupt_trace=gen_interrupt_trace, gen_dma_trace=gen_dma_trace, silent=not verbose)

def pool_func_gen_traces_forkserver(job):
    global pool_state_gentrace_proc
    input_path, bbl_trace_path, ram_trace_path, mmio_trace_path, bbl_set_path, mmio_set_path, bbl_hash_path, interrupt_trace_path, dma_trace_path = job
    if not pool_state_gentrace_proc.gen_trace(input_path, bbl_set_path, mmio_set_path, bbl_hash_path, bbl_trace_path, ram_trace_path, mmio_trace_path, interrupt_trace_path, dma_trace_path):
        logger.error(f"\n\n[ERROR] Hit abrupt end while trying to execute input {input_path}\n")
        exit(-1)

def pool_func_gen_traces_new_proc(job):
    global pool_arg_verbose, pool_arg_config_path, pool_arg_extra_args

    input_path, bbl_trace_path, ram_trace_path, mmio_trace_path, bbl_set_path, mmio_set_path, bbl_hash_path, interrupt_trace_path, dma_trace_path = job
    gen_traces(str(pool_arg_config_path), str(input_path),
        bbl_trace_path=bbl_trace_path, ram_trace_path=ram_trace_path, mmio_trace_path=mmio_trace_path,
        bbl_set_path=bbl_set_path, mmio_set_path=mmio_set_path, bbl_hash_path=bbl_hash_path,
        interrupt_trace_path=interrupt_trace_path, dma_trace_path=dma_trace_path, extra_args=pool_arg_extra_args, silent=not pool_arg_verbose
    )

def gen_all_missing_traces(projdir, trace_name_prefixes=None, log_progress=False, verbose=False, crashing_inputs=False, force_overwrite=False):
    if trace_name_prefixes is None:
        trace_name_prefixes = nc.TRACE_FILENAME_PREFIXES

    for maindir in nc.main_dirs_for_proj(projdir):
        gen_missing_maindir_traces(maindir, trace_name_prefixes, log_progress=log_progress, verbose=verbose, crashing_inputs=crashing_inputs, force_overwrite=force_overwrite)

def spawn_forkserver_emu_child(config_path, input_path, extra_args, silent=False):
    arg_list = gen_run_arglist(config_path, extra_args) + [input_path]

    # Set up pipes for AFL fork server communication
    control_fd_rd, control_fd_wr = os.pipe()
    status_fd_rd, status_fd_wr = os.pipe()

    os.dup2(control_fd_rd, FORKSRV_FD)
    os.dup2(status_fd_wr, FORKSRV_FD + 1)
    os.set_inheritable(FORKSRV_FD, True)
    os.set_inheritable(FORKSRV_FD + 1, True)

    # Close duplicated fds
    os.close(control_fd_rd)
    os.close(status_fd_wr)

    subprocess_env = os.environ
    subprocess_env.setdefault("__AFL_SHM_ID", "0")

    # Silence stdout/stderr if requested
    stdout, stderr = None, None
    if silent:
        stdout, stderr = subprocess.DEVNULL, subprocess.DEVNULL

    proc = subprocess.Popen(arg_list, stdout=stdout, stderr=stderr, pass_fds=[FORKSRV_FD, FORKSRV_FD + 1], env=subprocess_env)

    # Close opposing end of pipe
    os.close(FORKSRV_FD)
    os.close(FORKSRV_FD + 1)

    # Wait for emulator process to respond
    assert len(os.read(status_fd_rd, 4)) == 4

    return proc, control_fd_wr, status_fd_rd

class TraceGenProc:
    """
    Class which spawns an underlying emulator child to then generate
    traces quickly, given a stable configuration.

    This fakes the fuzzer side of the AFL fork server setup to the emulator
    so that the emulator can use snapshotting to quickly run multiple times.
    """
    uuid: str

    # Stable paths to pass arguments to emulator where we create symlinks later
    stable_input_path: Path = None
    stable_bbset_path: Path = None
    stable_bbhash_path: Path = None
    stable_mmioset_path: Path = None
    stable_bbtrace_path: Path = None
    stable_ramtrace_path: Path = None
    stable_mmiotrace_path: Path = None
    stable_interrupt_trace_path: Path = None
    stable_dma_trace_path: Path = None

    child_proc = None
    status_read_fd = None
    ctrl_write_fd = None
    config_path = None

    def __init__(self, config_path, extra_args=None, gen_bb_set=False, gen_mmio_set=False, gen_bb_hash=False, gen_bb_trace=False, gen_ram_trace=False, gen_mmio_trace=False, gen_interrupt_trace=False, gen_dma_trace=False, base_path="/tmp", silent=False):
        self.uuid = str(uuid.uuid4())

        self.stable_input_path = Path(os.path.join(base_path, ".trace_input_"+self.uuid))
        if gen_bb_set:
            self.stable_bbset_path = Path(os.path.join(base_path, ".trace_bbset_"+self.uuid))
        if gen_bb_hash:
            self.stable_bbhash_path = Path(os.path.join(base_path, ".trace_bbhash_"+self.uuid))
        if gen_mmio_set:
            self.stable_mmioset_path = Path(os.path.join(base_path, ".trace_mmioset_"+self.uuid))
        if gen_bb_trace:
            self.stable_bbtrace_path = Path(os.path.join(base_path, ".trace_bbtrace_"+self.uuid))
        if gen_ram_trace:
            self.stable_ramtrace_path = Path(os.path.join(base_path, ".trace_ramtrace_"+self.uuid))
        if gen_mmio_trace:
            self.stable_mmiotrace_path = Path(os.path.join(base_path, ".trace_mmiotrace_"+self.uuid))
        if gen_interrupt_trace:
            self.stable_interrupt_trace_path = Path(os.path.join(base_path, ".trace_interrupt_trace_"+self.uuid))

        if gen_dma_trace:
            self.stable_dma_trace_path = Path(os.path.join(base_path, ".trace_dma_trace_"+self.uuid))

        self.spawn_emulator_child(config_path, extra_args, gen_bb_set=gen_bb_set, gen_mmio_set=gen_mmio_set, gen_bb_hash=gen_bb_hash, gen_bb_trace=gen_bb_trace, gen_ram_trace=gen_ram_trace, gen_mmio_trace=gen_mmio_trace, gen_interrupt_trace=gen_interrupt_trace,gen_dma_trace=gen_dma_trace,silent=silent)

    def destroy(self):
        self.rm_links()
        self.kill_emulator_child()

    def __del__(self):
        self.destroy()

        try:
            super().__del__()
        except AttributeError:
            pass

    def spawn_emulator_child(self, config_path, extra_args=None, gen_bb_set=False, gen_mmio_set=False, gen_bb_hash=False, gen_bb_trace=False, gen_ram_trace=False, gen_mmio_trace=False, gen_interrupt_trace=False, gen_dma_trace=False, silent=False):
        extra_args = extra_args or []

        if gen_bb_set:
            extra_args += ["--bb-set-out", str(self.stable_bbset_path)]
        if gen_mmio_set:
            extra_args += ["--mmio-set-out", str(self.stable_mmioset_path)]
        if gen_bb_hash:
            extra_args += ["--bb-hash-out", str(self.stable_bbhash_path)]
        if gen_bb_trace:
            extra_args += ["--bb-trace-out", str(self.stable_bbtrace_path)]
        if gen_ram_trace:
            extra_args += ["--ram-trace-out", str(self.stable_ramtrace_path)]
        if gen_mmio_trace:
            extra_args += ["--mmio-trace-out", str(self.stable_mmiotrace_path)]
        if gen_interrupt_trace:
            extra_args += ["--interrupt-trace-out", str(self.stable_interrupt_trace_path)]
        if gen_dma_trace:
            extra_args += ["--dma-trace-out", str(self.stable_dma_trace_path)]

        self.child_proc, self.ctrl_write_fd, self.status_read_fd = spawn_forkserver_emu_child(config_path, self.stable_input_path, extra_args, silent=silent)

    def kill_emulator_child(self):
        logger.debug("[Trace Gen] kill_emulator_child")
        if self.status_read_fd is not None:
            os.close(self.status_read_fd)
            os.close(self.ctrl_write_fd)
            try:
                self.child_proc.kill()
            except OSError:
                pass

            self.status_read_fd = None
            self.ctrl_write_fd = None
            self.child_proc = None

    def rm_old_trace_links(self):
        for p in (self.stable_bbset_path, self.stable_mmioset_path, self.stable_bbhash_path, self.stable_bbtrace_path, self.stable_ramtrace_path, self.stable_mmiotrace_path, self.stable_interrupt_trace_path, self.stable_dma_trace_path):
            if p is not None:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass

    def rm_input_link(self):
        try:
            self.stable_input_path.unlink()
        except FileNotFoundError:
            pass

    def rm_links(self):
        self.rm_input_link()
        self.rm_old_trace_links()

    def setup_input_link(self, input_path):
        self.rm_input_link()

        # We always need an input
        self.stable_input_path.symlink_to(input_path)

    def setup_trace_links(self, bb_set_path=None, mmio_set_path=None, bb_hash_path=None, bbl_trace_path=None, ram_trace_path=None, mmio_trace_path=None, interrupt_trace_path=None, dma_trace_path=None):
        # Create Symlinks to input and output paths
        self.rm_old_trace_links()

        # For output paths, we may not need to create all
        if bb_set_path:
            self.stable_bbset_path.symlink_to(bb_set_path)
        if mmio_set_path:
            self.stable_mmioset_path.symlink_to(mmio_set_path)
        if bb_hash_path:
            self.stable_bbhash_path.symlink_to(bb_hash_path)
        if bbl_trace_path:
            self.stable_bbtrace_path.symlink_to(bbl_trace_path)
        if ram_trace_path:
            self.stable_ramtrace_path.symlink_to(ram_trace_path)
        if mmio_trace_path:
            self.stable_mmiotrace_path.symlink_to(mmio_trace_path)
        if interrupt_trace_path:
            self.stable_interrupt_trace_path.symlink_to(interrupt_trace_path)
        if dma_trace_path:
            self.stable_dma_trace_path.symlink_to(dma_trace_path)

    def gen_trace(self, input_path, bb_set_path=None, mmio_set_path=None, bb_hash_path=None, bbl_trace_path=None, ram_trace_path=None, mmio_trace_path=None, interrupt_trace_path=None, dma_trace_path=None):
        # First set up symlinks to the input file and the trace destinations
        self.setup_trace_links(bb_set_path, mmio_set_path, bb_hash_path, bbl_trace_path, ram_trace_path, mmio_trace_path, interrupt_trace_path, dma_trace_path)
        self.setup_input_link(input_path)

        return self.trigger_trace_gen()

    def gen_trace_no_trace_symlinks(self, input_path):
        self.setup_input_link(input_path)
        self.rm_old_trace_links()

        return self.trigger_trace_gen()

    def trigger_trace_gen(self):
        # And now, kick off child by sending go via control fd
        assert os.write(self.ctrl_write_fd, b"\0\0\0\0") == 4

        # Read two times from FD (one time for start, one time for emu finish)
        for _ in range(2):
            sock_read_len = len(os.read(self.status_read_fd, 4))
            if sock_read_len != 4:
                break

        # We have been successful in case the expected amount of bytes are read
        return sock_read_len == 4

class TraceGenerator:
    last_config_path = None

    trace_proc: TraceGenProc = None
    last_extra_args = None

    need_bbl_set = False
    need_mmio_set = False
    need_bb_hash = False
    need_bb_trace = False
    need_ram_trace = False
    need_mmio_trace = False
    need_interrupt_trace = False
    need_dma_trace = False

    silent: bool = False

    def __init__(self, silent=False):
        self.silent = silent

    def __del__(self):
        self.discard_trace_proc()

    def discard_trace_proc(self):
        if self.trace_proc:
            self.trace_proc.destroy()
            self.trace_proc = None

    def update_config(self, config_path, extra_args, gen_bb_set=False, gen_mmio_set=False, gen_bb_hash=False, gen_bb_trace=False, gen_ram_trace=False, gen_mmio_trace=False, gen_interrupt_trace=False, gen_dma_trace=False):
        config_changed = False
        if config_path != self.last_config_path:
            logger.info(f"Config path changed from {self.last_config_path} to {config_path}")
            self.last_config_path = config_path
            config_changed = True
        if extra_args != self.last_extra_args:
            logger.info(f"Extra args changed from {self.last_extra_args} to {extra_args}")
            self.last_extra_args = copy.copy(extra_args)
            config_changed = True
        is_trace_type_added = False
        if not self.need_bbl_set and gen_bb_set:
            self.need_bbl_set = gen_bb_set
            is_trace_type_added = True
        if not self.need_mmio_set and gen_mmio_set:
            self.need_mmio_set = gen_mmio_set
            is_trace_type_added = True
        if not self.need_bb_hash and gen_bb_hash:
            self.need_bb_hash = gen_bb_hash
            is_trace_type_added = True
        if not self.need_bb_trace and gen_bb_trace:
            self.need_bb_trace = gen_bb_trace
            is_trace_type_added = True
        if not self.need_ram_trace and gen_ram_trace:
            self.need_ram_trace = gen_ram_trace
            is_trace_type_added = True
        if not self.need_mmio_trace and gen_mmio_trace:
            self.need_mmio_trace = gen_mmio_trace
            is_trace_type_added = True
        if not self.need_interrupt_trace and gen_interrupt_trace:
            self.need_interrupt_trace = gen_interrupt_trace
            is_trace_type_added = True
        if not self.need_dma_trace and gen_dma_trace:
            self.need_dma_trace = gen_dma_trace
            is_trace_type_added = True
        if is_trace_type_added:
            logger.info(f"Got new required trace type")
            config_changed = True

        # If we need to switch to another config, kill current emulator child process
        if config_changed:
            logger.info(f"Discarding current trace process")
            self.discard_trace_proc()

        # If we do not have a child process already, create one now
        if self.trace_proc is None:
            logger.info(f"Creating new trace process for config path {config_path}")
            # Start child process
            self.trace_proc = TraceGenProc(config_path, extra_args, gen_bb_set=self.need_bbl_set, gen_mmio_set=self.need_mmio_set, gen_bb_hash=self.need_bb_hash,
                                        gen_bb_trace=self.need_bb_trace, gen_ram_trace=self.need_ram_trace, gen_mmio_trace=self.need_mmio_trace, gen_interrupt_trace=self.need_interrupt_trace, gen_dma_trace=self.need_dma_trace, silent=self.silent)

    def gen_trace(self, config_path, extra_args, input_path, bbl_set_path, mmio_set_path, bbl_hash_path, bbl_trace_path, ram_trace_path, mmio_trace_path, interrupt_trace_path, dma_trace_path):
        self.update_config(config_path, extra_args, gen_bb_set=bbl_set_path is not None, gen_mmio_set=mmio_set_path is not None, gen_bb_hash=bbl_hash_path is not None,
            gen_bb_trace=bbl_trace_path is not None, gen_ram_trace=ram_trace_path is not None, gen_mmio_trace=mmio_trace_path is not None, gen_interrupt_trace=interrupt_trace_path is not None, gen_dma_trace=dma_trace_path is not None)

        success = self.trace_proc.gen_trace(input_path, bbl_set_path, mmio_set_path, bbl_hash_path, bbl_trace_path, ram_trace_path, mmio_trace_path, interrupt_trace_path, dma_trace_path)

        return success

    def gen_temp_trace(self, config_path, extra_args, input_path, gen_bb_set=False, gen_mmio_set=False, gen_bb_hash=False, gen_bb_trace=False, gen_ram_trace=False, gen_mmio_trace=False, gen_interrupt_trace=False, gen_dma_trace=False):
        self.update_config(config_path, extra_args, gen_bb_set, gen_mmio_set, gen_bb_hash, gen_bb_trace, gen_ram_trace, gen_mmio_trace, gen_interrupt_trace, gen_dma_trace)

        success = self.trace_proc.gen_trace_no_trace_symlinks(input_path)

        return success


class TraceGenWorker(rq.Worker): #pylint: disable=too-many-instance-attributes
    trace_gen: TraceGenerator = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.trace_gen = TraceGenerator()

    def __del__(self):
        if self.trace_gen:
            self.trace_gen.discard_trace_proc()
        try:
            super().__del__()
        except AttributeError:
            pass

    def execute_job(self, job, queue): #pylint: disable=inconsistent-return-statements
        """ Execute a generation job. This can be either
        - a trace generation job
        - or a state generation job
        """
        kwargs = job.kwargs

        # For state generation and non-forkserver traces, forward to original implementation
        if queue.name == nc.REDIS_QUEUE_NAME_STATE_GEN_JOBS or \
            any(kwargs.get(argname) for argname in FORKSERVER_UNSUPPORTED_TRACE_ARGS):
            return super().execute_job(job, queue)

        bbl_set_path, mmio_set_path, bbl_hash_path = kwargs.get(ARGNAME_BBL_SET_PATH, None), kwargs.get(ARGNAME_MMIO_SET_PATH, None), kwargs.get(ARGNAME_BBL_HASH_PATH, None)
        bbl_trace_path, ram_trace_path, mmio_trace_path = kwargs.get(ARGNAME_BBL_TRACE_PATH, None), kwargs.get(ARGNAME_RAM_TRACE_PATH, None), kwargs.get(ARGNAME_MMIO_TRACE_PATH, None)
        interrupt_trace_path = kwargs.get(ARGNAME_INTERRUPT_TRACE_PATH, None)
        dma_trace_path = kwargs.get(ARGNAME_DMA_TRACE_PATH, None)

        self.prepare_job_execution(job)
        job.started_at = datetime.datetime.now(datetime.timezone.utc)

        config_path, input_path = job.args
        extra_args = kwargs.get(ARGNAME_EXTRA_ARGS, [])

        success = self.trace_gen.gen_trace(config_path, extra_args, input_path, bbl_set_path, mmio_set_path, bbl_hash_path, bbl_trace_path, ram_trace_path, mmio_trace_path, interrupt_trace_path, dma_trace_path)
        job.ended_at = datetime.datetime.now(datetime.timezone.utc)
        logger.info(f"Generated traces for {os.path.basename(input_path)} in {(job.ended_at-job.started_at).microseconds} us")
        if success:
            # Job success
            job.set_status(rq.job.JobStatus.FINISHED)

            self.handle_job_success(job=job, queue=queue,
                started_job_registry=queue.started_job_registry)
        else:
            # Job fail
            self.handle_job_failure(job=job, queue=queue,
                started_job_registry=queue.started_job_registry)

            # The emulator is likely in a bad state now, kill child
            logger.warning(f"[Trace Gen Job] got a failed tracing job (which ran from {job.started_at} to {job.ended_at}). closing file pipe FDs for kill + respawn.")
            self.trace_gen.discard_trace_proc()

        self.set_state(WorkerStatus.IDLE)
