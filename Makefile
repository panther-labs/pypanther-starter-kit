test:
	poetry run pytest ./tests

pypanther-test:
	poetry run pypanther test

fmt:
	poetry run ruff format .

lint:
	poetry run ruff check .

upload:
	poetry run pypanther upload

install:
	poetry install --no-root