PYTHON ?= python

.PHONY: install test lint security audit run build container-check
install:
	$(PYTHON) -m pip install --require-hashes --only-binary=:all: -r requirements-dev.lock
test:
	$(PYTHON) -m pytest
lint:
	$(PYTHON) -m ruff check src tests scripts
	$(PYTHON) -m ruff format --check src tests scripts
security:
	$(PYTHON) -m bandit -r src scripts/resolve_base_image.py scripts/scan_image_layers.py scripts/smoke_local.py -c pyproject.toml
audit:
	$(PYTHON) -m pip_audit -r requirements.lock --require-hashes --disable-pip
run:
	PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m secure_api.main
build:
	docker build -t secure-fastapi:phase2 .
container-check:
	pwsh -NoProfile -File scripts/Test-Container.ps1
