# pypanther-starter-kit

Detection-As-Code V2 examples and starter kit.

## How To Use PyPanther Starter Kit

## Project Layout

The starter kit contains a few key top-level files.

* `main.py`: This contains a suggested layout to how to organize your main file, which houses the controlling logic when using PyPanther.
* `Makefile`: Contains a small set of make commands that can be used when using this repo. All the commands can be run outside of make too. Run any of them with `make <cmd>`.
* `pyproject.toml`: Specifies project dependencies and configuration. This file can work with many Python tools. The starter kit has been designed to work out-of-the-box with the `poetry` tool.
* `poetry.lock`: The lock file used by `poetry` which will ensure consistant downloads of dependencies between machines and sessions.

The starter kit contains also has a few key folders to understand.

* `rules`: This folder is meant to hold all your custom and fine-tuned rules. It is organized by log type, but can be adjusted to suit your needs.
* `.github`: Holds automation configurations used by GitHub to ensure that the all tests pass and files are linted. That way you can make sure all PR's look good before merging them to your main branch. If you are not using GitHub, this can be safely deleted.

## Configuring

## More Resources
