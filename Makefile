PYTHON ?= python3

.PHONY: test lint lint-fix

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check

lint-fix:
	$(PYTHON) -m ruff check --fix
