PYTHON ?= python3

.PHONY: test lint lint-fix build run

build:
	$(PYTHON) scripts/build.py

run:
	$(PYTHON) scripts/build.py --run

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check

lint-fix:
	$(PYTHON) -m ruff check --fix
