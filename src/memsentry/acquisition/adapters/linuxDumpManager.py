"""Linux-specific live memory dump adapter.

Invoked by ``dump_manager.DumpManager`` when the host OS is Linux. Wrap a
single approved acquisition tool for this platform, write a raw image into the
case directory, and report byte-level progress. Privilege checks and tool
availability belong here; Volatility plugin execution does not.
"""
