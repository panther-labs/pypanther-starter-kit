test:
	poetry run pypanther test

fmt:
	poetry run ruff check --select I --fix .
	poetry run ruff format .

lint: fmt
	poetry run ruff check --fix .
	poetry run ruff format --check .

upload:
	poetry run pypanther upload

install:
	poetry install --no-root