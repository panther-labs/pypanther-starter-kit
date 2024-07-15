test:
	poetry run pypanther test

fmt:
	poetry run ruff format .

format: fmt

lint:
	poetry run ruff check .

upload:
	poetry run pypanther upload

install:
	poetry install --no-root