"""Cross-process serialization for stateful Gym 003 operations."""

from __future__ import annotations

import fcntl
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


_THREAD_LOCK = threading.RLock()
_LOCAL = threading.local()


@contextmanager
def exclusive_operation(
    state_dir: str | Path = "/var/lib/gym/state", *, timeout: float = 10.0
) -> Iterator[None]:
    """Hold the shared scenario lock, failing safely instead of racing a job."""

    with _THREAD_LOCK:
        depth = int(getattr(_LOCAL, "depth", 0))
        if depth:
            _LOCAL.depth = depth + 1
            try:
                yield
            finally:
                _LOCAL.depth -= 1
            return

        directory = Path(state_dir)
        directory.mkdir(parents=True, exist_ok=True)
        lock_path = directory / ".operation.lock"
        with lock_path.open("a+") as handle:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("another Gym 003 stateful operation is running")
                    time.sleep(0.1)
            _LOCAL.depth = 1
            try:
                yield
            finally:
                _LOCAL.depth = 0
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
