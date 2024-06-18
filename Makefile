test:
	poetry run pytest .

pypanther-test:
	poetry run pypanther test

fmt:
	poetry run ruff format .

lint:
	poetry run ruff check .
	poetry run mypy .

upload:
	poetry run pypanther upload

install:
	poetry install --no-root