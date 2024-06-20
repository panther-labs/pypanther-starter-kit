pytest:
	poetry run pytest ./tests

test:
	poetry run pypanther test

fmt:
	poetry run ruff format .

lint:
	poetry run ruff check .

upload:
	poetry run pypanther upload

install:
	poetry install --no-root