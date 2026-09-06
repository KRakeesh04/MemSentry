"""Progress and remaining-time reporting for a live memory dump.

The GUI must stay responsive while capture runs on a worker. This module will
hold the progress model: bytes written, total expected size, elapsed time, and
an ETA refined as throughput is observed (RAM size ÷ write rate), not a fixed
guess per OS.

Adapters should report byte counts here. ``DumpManager`` and the worker should
forward those events to the GUI. Do not parse Volatility output or touch the
finished image except to measure size for the estimate.
"""
