import os

from typing import List

from .. import naming_conventions as nc

"""
Utilities to find fuzzware project directories in a directory tree
"""

def find_projdirs(basedir: str, is_entry=True) -> List[str]:
    res = []

    if is_entry:
        if not os.path.exists(basedir):
            return []
        if nc.is_project_base_dir(basedir):
            return [ basedir ]

    with os.scandir(basedir) as it:
        for entry in it:
            if not entry.is_dir():
                continue

            # Collect project dirs (but stop scanning from a project base dir)
            if nc.is_project_base_dir(entry.path):
                res.append(entry.path)
            else:
                res.extend(find_projdirs(entry.path, is_entry=False))

    return res
