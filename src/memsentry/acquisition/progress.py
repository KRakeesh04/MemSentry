"""Progress and remaining-time reporting for live memory capture."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import psutil


@dataclass(frozen=True, slots=True)
class ProgressDetails:
    """A UI-ready snapshot of the current acquisition progress."""

    bytes_written: int
    expected_bytes: int
    elapsed_seconds: float
    percentage: float
    throughput_bytes_per_second: float
    eta_seconds: float | None
    completed: bool = False


ProgressListener = Callable[[ProgressDetails], None]


def physical_memory_bytes() -> int:
    """Return the host's physical memory size for percentage estimation."""

    return psutil.virtual_memory().total


def calculate_progress(
    bytes_written: int,
    elapsed_seconds: float,
    expected_bytes: int | None = None,
    *,
    completed: bool = False,
) -> ProgressDetails:
    """Calculate percentage, throughput, and ETA from a capture update.

    ``expected_bytes`` defaults to physical RAM. The percentage is capped at
    99 while capture is active because acquisition tools can omit pages or
    produce a slightly different output size. A successful final update must
    set ``completed=True`` to return 100 percent.
    """

    if bytes_written < 0:
        raise ValueError("bytes_written cannot be negative")
    if elapsed_seconds < 0:
        raise ValueError("elapsed_seconds cannot be negative")
    if expected_bytes is not None and expected_bytes <= 0:
        raise ValueError("expected_bytes must be positive")

    expected_bytes = expected_bytes or physical_memory_bytes()
    throughput = bytes_written / elapsed_seconds if elapsed_seconds > 0 else 0.0
    if completed:
        percentage = 100.0
        eta_seconds = 0.0
    else:
        percentage = min(99.0, bytes_written / expected_bytes * 100)
        eta_seconds = (
            max(0.0, expected_bytes - bytes_written) / throughput
            if throughput > 0
            else None
        )

    return ProgressDetails(
        bytes_written=bytes_written,
        expected_bytes=expected_bytes,
        elapsed_seconds=elapsed_seconds,
        percentage=percentage,
        throughput_bytes_per_second=throughput,
        eta_seconds=eta_seconds,
        completed=completed,
    )


class ProgressTracker:
    """Callable adapter from raw byte updates to progress details."""

    def __init__(
        self,
        expected_bytes: int | None = None,
        listener: ProgressListener | None = None,
    ) -> None:
        self.expected_bytes = expected_bytes or physical_memory_bytes()
        self.listener = listener

    def __call__(
        self,
        bytes_written: int,
        elapsed_seconds: float | None = None,
    ) -> ProgressDetails:
        """Return details and optionally notify the UI listener."""

        details = calculate_progress(
            bytes_written,
            elapsed_seconds or 0.0,
            self.expected_bytes,
        )
        if self.listener is not None:
            self.listener(details)
        return details

    def complete(self, bytes_written: int, elapsed_seconds: float) -> ProgressDetails:
        """Return and publish the final 100-percent snapshot."""

        details = calculate_progress(
            bytes_written,
            elapsed_seconds,
            self.expected_bytes,
            completed=True,
        )
        if self.listener is not None:
            self.listener(details)
        return details
