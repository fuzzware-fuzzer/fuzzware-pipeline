from queue import Queue
from time import time
import os
from fuzzware_pipeline.naming_conventions import SESS_FILENAME_PREFIX_DMA_CFG_CANDIDATE

from watchdog.events import FileSystemEventHandler


class NewDMACandidateConfigHandler(FileSystemEventHandler):
    queue: Queue

    def __init__(self, queue):
        super(NewDMACandidateConfigHandler, self).__init__()
        self.queue = queue

    def on_created(self, event):
        if os.path.basename(event.src_path).startswith(SESS_FILENAME_PREFIX_DMA_CFG_CANDIDATE):
            self.queue.put((time(), event.src_path))
