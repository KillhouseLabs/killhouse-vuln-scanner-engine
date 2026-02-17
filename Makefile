.PHONY: setup lint format test

setup:
	pip install -r requirements.txt
	bash scripts/setup-hooks.sh

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

test:
	pytest -m "not integration" -q
