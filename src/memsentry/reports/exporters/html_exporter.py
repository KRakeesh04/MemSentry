from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from memsentry.models.report import ReportData


class HtmlReportExporter:
    """Exports ReportData to a standalone HTML file."""

    def __init__(self, template_dir: Path | None = None) -> None:
        if template_dir is None:
            template_dir = Path(__file__).parent.parent / "templates"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)

    def export(self, data: ReportData, output_path: Path) -> None:
        template = self.env.get_template("report.html.j2")
        # dump dictionary so we can iterate easily in Jinja
        data_dict = data.model_dump()
        html_content = template.render(report=data_dict)
        output_path.write_text(html_content, encoding="utf-8")
