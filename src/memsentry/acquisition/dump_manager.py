"""Orchestrate live memory acquisition for a case.

This module is the single entry point for capturing RAM on the examination
host. It is not part of Volatility analysis.

Responsibilities (when implemented):

- Accept a GUI choice of an existing dump file vs a live dump.
- For live capture, detect the *host* OS and delegate to the matching adapter
  under ``acquisition/adapters/``.
- Choose an output path in the case directory (never overwrite evidence).
- Start the dump, estimate remaining time from RAM size and write throughput,
  and emit progress via ``progress.py``.
- After the raw file is written, hash it (SHA-256) and hand the path to
  evidence registration. ``AnalysisService`` then analyses that file the same
  way it analyses a user-selected dump.

Do not call Volatility plugins from this package. Live acquisition remains a
stretch goal; the MVP still registers previously acquired images only.
"""
