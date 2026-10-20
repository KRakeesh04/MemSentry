PYTHON ?= python3

.PHONY: test test-linux test-windows test-macos lint lint-fix build run

build:
	$(PYTHON) scripts/build.py

run:
	$(PYTHON) scripts/build.py --run

test:
	$(PYTHON) -m pytest

test-linux:
	$(PYTHON) -m pytest --test-os=linux

test-windows:
	$(PYTHON) -m pytest --test-os=windows

test-macos:
	$(PYTHON) -m pytest --test-os=macos

lint:
	$(PYTHON) -m ruff check

lint-fix:
	$(PYTHON) -m ruff check --fix
