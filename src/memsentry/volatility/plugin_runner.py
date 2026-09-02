class PluginRunner:
    """Orchestrates the execution of Volatility plugins and the processing of their results."""

    def __init__(self, adapter, plugin_registry, plugin_run_repository):
        self.adapter = adapter
        self.plugin_registry = plugin_registry
        self.plugin_run_repository = plugin_run_repository

    def run_plugin(self, evidence_path: str, analysis_run_id: int, plugin_id: str, os_type: str):
        """Run a Volatility plugin and process its results."""
        # 1. Create a plugin_runs database record.
        # 2. Mark the run as running.
        # 3. Invoke Volatility against the read-only evidence image.
        # 4. Capture stdout, stderr, duration, and status.
        # 5. Save raw output outside the evidence file.
        # 6. Calculate the raw-output hash.
        # 7. Mark the plugin run as completed or failed.
        # 8. Pass raw output to the selected parser.
        # 9. Persist normalized artifacts and provenance.

        pass