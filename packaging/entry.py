"""PyInstaller entry point, including an evidence-free bundle health check."""

import sys
from multiprocessing import freeze_support

from memsentry.main import main

if __name__ == "__main__":
    freeze_support()
    if "--smoke-test" in sys.argv:
        from memsentry.app.bundle_check import check_bundle

        check_bundle()
    else:
        main()
