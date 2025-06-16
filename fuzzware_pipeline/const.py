DEFAULT_IDLE_BBL = 0xffffffe0

EMULATION_RUN_TIMEOUT = 10000

RQ_STATEGEN_JOB_TIMEOUT = 3600 # 1h, for the case where there are large numbers of MMIO contexts
RQ_MODELING_JOB_TIMEOUT = 300 # 5 minutes
RQ_DMA_SNIPPET_JOB_TIMEOUT = 300 # 5 minutes
RQ_DMA_SUMMARY_JOB_TIMEOUT = 3600 # 1h
# We are setting high times to live as we experienced some job losses before
RQ_RESULT_TTL = 24*3600  # 24h
RQ_JOB_TTL = 2*24*3600  # 48h
RQ_JOB_FAILURE_TTL = 24*3600 # 24h

MAX_FUZZER_DRYRUN_SECONDS = 20

# Pipeline constants
EVENT_MIN_WAIT = 1 # 1 second of wait after file event to make sure files are written and we are not racing with inotify
CONFIG_UPDATE_FORCE_FUZZER_RESTART_LIMIT = 100

# Don't renew config without giving the fuzzer some time to discover inputs around new accesses
CONFIG_UPDATE_MIN_TIME_SINCE_NEW_BB_DISCOVERY = 2 * 60 # 2 minutes
DMA_ANALYSIS_RERUN_TIMEOUT = 10 * 60 # 10 minutes

IDLE_BUSYLOOP_SLEEP = 0.1
IDLE_COUNT_HOUSEKEEPING = 5 # 5 seconds (TODO: 0.1 * 5 = 0.5 seconds?)
IDLE_COUNT_DMA_DETECTION = 10 * 60 # 1 minute
LOOP_COUNT_HOUSEKEEPING = 200   # 20 seconds

FIRST_STAT_PRINT_DELAY = 180
STAT_PRINT_INTERVAL = 30

MAX_NUM_DEAD_FUZZER_RESTARTS = 10
MAX_NUM_MODELS_PER_PC = 32
