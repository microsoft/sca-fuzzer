"""
File: Module managing a worker pool for concurrent task execution.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os
import signal
import time
import multiprocessing
from typing import Callable, Iterable, TypeVar, Any

from .logger import Logger

T = TypeVar('T')

_logger = Logger("WorkerPool")

# How often (seconds) to poll for results and check for worker crashes / memory pressure.
_POLL_INTERVAL: int = 5


# ==================================================================================================
# Pool initializer — runs once in every fresh worker process
# ==================================================================================================
def _init_worker() -> None:
    """
    Pool initializer executed in each worker process.

    * Raises the worker's OOM score so the Linux OOM killer targets workers before the parent.
    * Restores the default SIGTERM handler so that pool.terminate() can
      shut workers down cleanly
    """
    # Raise OOM score (best-effort; silently ignored on non-Linux)
    try:
        with open(f"/proc/{os.getpid()}/oom_score_adj", "w") as f:
            f.write("400\n")
    except (PermissionError, FileNotFoundError, OSError):
        pass

    # Ensure SIGTERM is not ignored
    signal.signal(signal.SIGTERM, signal.SIG_DFL)


# ==================================================================================================
# Memory monitoring
# ==================================================================================================
def _memory_pressure_over_threshold(mem_pressure_threshold: float) -> bool:
    """
    Return True if available system memory is below the given threshold.
    Returns False on non-Linux platforms where /proc/meminfo is unavailable.
    """
    try:
        with open("/proc/meminfo") as f:
            info = {}
            for line in f:
                parts = line.split()
                if parts[0] in ("MemTotal:", "MemAvailable:"):
                    info[parts[0]] = int(parts[1])
                if len(info) == 2:
                    break
        return info["MemAvailable:"] / info["MemTotal:"] < mem_pressure_threshold
    except (FileNotFoundError, KeyError, OSError, ZeroDivisionError):
        return False


# ==================================================================================================
# Public API
# ==================================================================================================
def send_to_worker_pool(task: Callable[..., T],
                        work_items: Iterable[Any],
                        num_workers: int,
                        on_complete: Callable[[T], None],
                        task_timeout: int = 3600,
                        mem_pressure_threshold: float = 0.10) -> None:
    """
    Execute *task* for every element in *work_items* across *num_workers*
    parallel processes, calling *on_complete* with each result as it arrives.

    NOTE: The worker pool frequently encounters OOM conditions due to the memory-hungry
          nature of trace analysis. The following design choices are made to mitigate this:
      - ``forkserver`` context: workers fork from a lean server process, not
        the (potentially large) parent, reducing copy-on-write overhead.
      - ``maxtasksperchild=1``: each worker is recycled after completing one
        task, so all memory accumulated during trace analysis is freed.
      - Workers raise their own ``oom_score_adj`` so the kernel's OOM killer
        preferentially targets them over the parent.
      - The parent monitors ``/proc/meminfo`` after every completed task and
        terminates the pool early if available memory drops below
        *mem_pressure_threshold*.
      - Broken-pipe / connection-reset errors are still caught as a fallback.

    :param task: Callable to execute in each worker. Must be picklable.
    :param work_items: Iterable of arguments; each element is passed as the
           single argument to *task*.
    :param num_workers: Number of parallel worker processes.
    :param on_complete: Callback invoked in the parent with each result
           returned by *task*.
    :param task_timeout: Seconds to wait for a single task before giving up.
    :param mem_pressure_threshold: Fraction (0.0-1.0) of total RAM. If available memory
           drops below this after a task completes, the pool is terminated early.
    """
    # Use forkserver so workers fork from a lean server process rather than
    # the (potentially large) parent, minimising COW page-fault overhead.
    ctx = multiprocessing.get_context('forkserver')

    with ctx.Pool(num_workers, initializer=_init_worker, maxtasksperchild=1) as pool:

        # Install the crash monitor *before* submitting any work so we
        # catch signals from the very first batch of workers.
        results_iter = pool.imap_unordered(task, work_items, chunksize=1)

        # Deadline for receiving the *next* result.  Reset after every
        # successful result so that each individual task gets the full
        # task_timeout budget.
        deadline = time.monotonic() + task_timeout

        while True:
            # --- fetch next result (short poll) ---
            try:
                result = results_iter.next(timeout=_POLL_INTERVAL)
            except StopIteration:
                break
            except multiprocessing.TimeoutError:
                # No result arrived in _POLL_INTERVAL seconds — check for
                # problems before polling again.

                # 1. Overall per-task timeout exceeded?
                if time.monotonic() >= deadline:
                    _logger.warning("Timed out waiting for a worker "
                                    f"(timeout={task_timeout}s). "
                                    "Terminating worker pool.")
                    pool.terminate()
                    break

                # 2. Memory pressure (proactive)?
                if _memory_pressure_over_threshold(mem_pressure_threshold):
                    _logger.error("Available memory dropped below "
                                  f"{mem_pressure_threshold * 100:.0f}%. "
                                  "Terminating worker pool to prevent OOM.")
                    pool.terminate()
                    break

                # Nothing wrong yet — keep polling.
                continue

            except (BrokenPipeError, ConnectionResetError, EOFError):
                _logger.error("A worker process was killed unexpectedly. "
                              "This is almost certainly the Linux OOM killer — "
                              "check 'dmesg | tail' for confirmation. "
                              "Terminating remaining workers.")
                pool.terminate()
                break

            # --- deliver result to caller; reset deadline ---
            deadline = time.monotonic() + task_timeout
            on_complete(result)

            # --- check memory pressure ---
            if _memory_pressure_over_threshold(mem_pressure_threshold):
                pool.terminate()
                break
