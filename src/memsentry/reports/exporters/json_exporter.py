from pathlib import Path

from memsentry.models.report import ReportData


class JsonReportExporter:
    """Exports ReportData to a JSON file."""

    def export(self, data: ReportData, output_path: Path) -> None:
        # We can use Pydantic's model_dump_json
        json_data = data.model_dump_json(indent=2)
        output_path.write_text(json_data, encoding="utf-8")
