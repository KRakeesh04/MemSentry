"""macOS-specific live memory dump adapter.

Invoked by ``dump_manager.DumpManager`` when the host OS is macOS. This is
stretch work (macOS analysis is already outside the MVP). If implemented, wrap
a single approved acquisition tool, write a raw image into the case directory,
and report progress. Do not call Volatility from this adapter.
"""
