from __future__ import annotations

from pytest import approx

from memsentry.acquisition.progress import ProgressTracker, calculate_progress


def test_calculate_progress_caps_active_capture_at_99_percent() -> None:
    details = calculate_progress(900, 10, expected_bytes=1_000)

    assert details.percentage == 90.0
    assert details.throughput_bytes_per_second == 90.0
    assert details.eta_seconds == approx(1.1111111111111112)
    assert details.completed is False


def test_completed_progress_returns_100_percent() -> None:
    details = calculate_progress(1_000, 10, expected_bytes=1_000, completed=True)

    assert details.percentage == 100.0
    assert details.eta_seconds == 0.0


def test_tracker_returns_details_and_notifies_listener() -> None:
    updates = []
    tracker = ProgressTracker(expected_bytes=1_000, listener=updates.append)

    details = tracker(500, 5)

    assert details.percentage == 50.0
    assert updates == [details]
