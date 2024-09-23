# pypanther-starter-kit

Detection-As-Code V2 examples and starter kit.

## Getting Started

To get started with this project, you'll need to clone the repository, install the necessary dependencies, and then run tests to ensure everything is set up correctly.

### Prerequisites

Before you begin, make sure you have the following installed:
- Git
- Make
- Python (check the `pyproject.toml` file for the required version)
- Poetry

Ensure that Poetry is using the correct version of Python by running `poetry env use path/to/python3.11`

### Local Environment Recommendations

It is vitally important to understand how your local environment is set up when running a python project.
There are many different ways to go about doing it. 
The following set up is how the Panther team recommends you set things up.
Doing it this way will help you avoid potential problems with package versions and python versions; as well as, making it easier to get support from the Panther team when issues do arise. 

#### Brew

Some of the following tools are installed via [Homebrew](https://brew.sh/). 
Please install it if you are using a Mac computer. 

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Make

If you don't use `make`, we encourage you to [download](https://formulae.brew.sh/formula/make) it. 
This project utilizes a [Makefile](./Makefile) to help with running common commands. 

#### Python Version

Python versions can be managed in many different ways.
We recommend using [Pyenv](https://github.com/pyenv/pyenv?tab=readme-ov-file#installation). 
If you are already using a python version management tool, or have python installed any other way, but decide you want to use Pyenv, we recommend uninstalling all other python versions to avoid any troubles or confusion. 

A handy way to know if python is already installed is by running:
```bash
which python
```

After installing Pyenv, you can set your python version by running the following:
```bash
pyenv install 3.11
pyenv global 3.11
```

#### Virtual Environment

A virtual environment is a contained local environment on your machine that has everything it needs to do what it needs to do. 
When working with python projects, we highly recommend using a virtual environment.
This way, if you have multiple projects, the dependencies of one won't interfere with the dependencies of the other. 
Most importantly, environments will be reproducible. 

The most common python virtual environment (venv) managers are `venv`, `pipenv`, `conda`, and `poetry`.
We recommend `poetry` because of its ease-of-use, extensibility, and sophisticated dependency conflict resolution algorithm. 

To download, follow the instructions [here](https://python-poetry.org/docs/).
The instructions recommend installing with [pipx](https://pipx.pypa.io/stable/installation/).
You can use `pip` (which comes with downloading python) as well. 

`poetry` utilizes a `pyproject.toml` file, which is a standardized file that many python tools use, for its configuration settings.
The starter kit already has [one](./pyproject.toml) defined for you. 

Once you install `poetry`, **all python commands should be run inside the poetry shell**. 
Even in your CI pipeline. 
More info on that [here](https://python-poetry.org/docs/basic-usage/#using-your-virtual-environment).
We have a [Makefile](./Makefile) that takes care of that for you.

### Installation

Follow these steps to get your development environment set up:

1. **Clone the repository**

    First, clone the repository to your local machine using Git:

    ```bash
    git clone git@github.com:panther-labs/pypanther-starter-kit.git
    ```

    Navigate into the repository directory:

2. **Install dependencies**

    Use the `make` command to install the necessary dependencies:

    ```bash
    make install
    ```

    This command sets up the environment and installs all the required Python packages.

3. **Running Tests**

    To validate that everything is set up correctly, you can run the predefined tests using the following command:

    ```bash
    make test
    ```

    This command runs the test suite and outputs the results, allowing you to verify that the installation was successful and that the project is working as expected.

    When developing, you may also use `pypanther test` for access to more command-line flags and arguments.

## Development

This repository serves as a bootstrap for the development of the new v2 `pypanther` framework, providing a foundational structure and essential components to accelerate the development process.

### File Structure

The repository is organized into several key directories and files to help you navigate and understand the structure easily. Here's a brief overview:

- **`rules/`**: This directory contains custom rules that are grouped by log type family. Each folder may also include longer sample events.

- **`helpers/`**: The `helpers/` directory is home to generic helper functions. These functions are designed to be reusable and can be utilized either in rules or filters. Their purpose is to simplify the code in the main logic by abstracting common tasks into functions.

- **`main.py`**: This is the main file of the repository. It controls the entire configuration for `pypanther`. The `main.py` file orchestrates which rules are imported and overridden with custom configurations.

- **`filters/`**: The `filters/` directory is dedicated to global include/exclude logic that can be applied across various rules. This allows for a centralized management of filtering criteria, making it easier to maintain consistency and efficiency in how rules are overridden.

Each of these components plays a vital role in the functionality of the `pypanther` framework, ensuring that the system is modular, easy to navigate, and extendable for future enhancements.

### Setting Your Configuration

The `main.py` and all other content in this repository serve as examples to build your configuration. For full documentation and functionality, [check out our docs](https://docs.panther.com/).

In order to interact with Panther, you will need to set up your Panther API key and Panther host. This can be done by setting the `PANTHER_API_KEY` and `PANTHER_API_HOST` environment variables.

## CI/CD Workflow

An example [GitHub workflow](https://github.com/panther-labs/pypanther-starter-kit/blob/main/.github/workflows/upload.yml) is provided to upload your configured ruleset to your Panther instance when PRs are merged to `release` branch.  `API_HOST` and `API_TOKEN` must be configured in your GitHub repository secrets.

An example process might look like this:

- PRs are merged to `main` as new rules are developed and existing rules are tuned.

- When you are ready to update your Panther instance, create a PR from `main` to `release`.

- Merging the PR to `release` automatically updates Panther, making the `release` branch the single source of truth for your Panther configuration!

## License

This project is licensed under the [AGPL-3.0 License] - see the LICENSE.txt file for details.
