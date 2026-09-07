"""Tests for main entry point and orchestrator timeout configuration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from memsentry.main import main


def test_main_configures_analysis_orchestrator_timeout(tmp_path: Path) -> None:
    with (
        patch("memsentry.main.Database") as mock_db_cls,
        patch("memsentry.main.create_application") as mock_create_app,
        patch("memsentry.main.AnalysisOrchestrator") as mock_orchestrator_cls,
    ):
        mock_db = MagicMock()
        mock_db_cls.return_value = mock_db

        mock_app = MagicMock()
        mock_create_app.return_value = mock_app

        main()

        mock_orchestrator_cls.assert_called_once()
        kwargs = mock_orchestrator_cls.call_args.kwargs
        assert kwargs["timeout_seconds"] == 900.0
