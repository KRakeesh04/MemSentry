from memsentry.gui.application import create_application


def main() -> None:
    app = create_application()
    app.exec()
