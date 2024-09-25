# pypanther-starter-kit

`pypanther` is a Python-native detection framework designed to significantly reduce the overhead of rule management, ensure smooth integration with CI/CD workflows, and enhance the effectiveness and actionability of alerts.

The starer kit serves as a bootstrap for the `pypanther` framework, providing a foundational structure and essential components to accelerate the rule development process. If you are not yet a Panther user, please reach out to us to [get a demo](https://panther.com/product/request-a-demo/)!

Leveraging `pypanther` leads to a more agile and responsive SecOps program, enabling teams to focus more on mitigating risks and responding to incidents instead of managing custom scripts for detection engineering.

Here's an example `main.py` centered on GitHub rules:

```python
from pypanther import get_panther_rules, register, LogType, Severity
from pypanther.rules.github import GitHubActionFailed

# Get all built-in GitHub Audit rules
git_rules = get_panther_rules(log_types=[LogType.GITHUB_AUDIT])

# Set overrides and tune your rule
GitHubActionFailed.override(
    enabled=True, dedup_period_minutes=60*8,
)
GitHubActionFailed.extend(
    tags=["CorpSec"],
)
GitHubActionFailed.MONITORED_ACTIONS = {
	"main_app": ["code_scanning"],
}

# A filter function to check for repo automation
def github_is_bot_filter(event):
	return bool(event.get("actor_is_bot"))

# Excluding this activity from our built-in rules
for rule in git_rules:
	rule.extend(exclude_filters=[is_bot])

# Registering and enabling rules to be uploaded and tested
register(git_rules)
```

## Getting Started

Clone the repo, install dependencies, and then run tests to ensure everything is set up correctly.

### Prerequisites

Before you begin, make sure you have the following installed:

- **Git**
- **Brew**: Some of the tools above are installed via [Homebrew](https://brew.sh/). Please install it if you are on MacOS using your preferred method on their site.
- **Make**: If you don't use `make`, we encourage you to [download](https://formulae.brew.sh/formula/make) it. This project utilizes a [Makefile](./Makefile) to help with running common test and lint commands.
- **Python**: If you are currently using a different Python version management tool or have Python installed through another method, but decide to switch to [Pyenv](https://github.com/pyenv/pyenv), we recommend uninstalling all other Python versions to prevent any potential issues or confusion. A handy way to check that python is installed is by running:
    ```bash
    which python
    ```
    After installing Pyenv, you can set your python version by running the following:
    ```bash
    pyenv install 3.11
    pyenv global 3.11
    ```
- **Poetry**: Ensure that Poetry is installed and using the correct version of Python by running `poetry env use path/to/python3.11`. We recommend `poetry` due to its ease-of-use, extensibility, and sophisticated dependency conflict resolution algorithm. To download, follow the instructions [here](https://python-poetry.org/docs/), which recommend installing with [pipx](https://pipx.pypa.io/stable/installation/). `poetry` utilizes a `pyproject.toml` file for its configuration settings, and the starter kit already has [already defined one](./pyproject.toml) for you. Once you install `poetry`, **all python commands should be run inside the poetry shell**, even in your CI pipeline, more info on that [here](https://python-poetry.org/docs/basic-usage/#using-your-virtual-environment).

### Starter Kit Installation

Follow these steps to get your development environment set up:

1. **Clone the repository**

    First, clone the repository to your local machine using Git:

    ```bash
    git clone git@github.com:panther-labs/pypanther-starter-kit.git
    ```

    Navigate into the `pypanther-starter-kit` directory:

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

### File Structure

`pypanther`'s primary configuration file `main.py` is located in the root directory and the remainder content is organized into several key directories under the `content/` folder:

- **`main.py`**: This is the main file of the repository. It controls the entire configuration for `pypanther`. The `main.py` file orchestrates which rules are imported and overridden with custom configurations.

- **`content/rules/`**: This directory contains customer-defined rules that are grouped by log type family. Each folder may also include longer sample events for `RuleTest`s.

- **`content/helpers/`**: The `helpers/` directory is home to generic helper functions. These functions are designed to be reusable and can be utilized either in rules or filters. Their purpose is to simplify the code in the main logic by abstracting common tasks into functions.

- **`content/overrides/`**: The `overrides/` directory is dedicated for managing your overrides to built-in rules. We recommend defining new rule override functions (like title or severity), attribute overrides (like include_filters), and mass-updates using for loops using the `apply_overrides()` function. Check the `content/rules` folder for an example.

### Setting Your Configuration

The `main.py` (and all other content in this repository) serves as examples to build your configuration. Read the [full documentation](https://docs.panther.com/detections/pypanther) to learn all of the paradigms.

To interact with your Panther instance via `pypanther upload`, you'll need to set the `PANTHER_API_KEY` and `PANTHER_API_HOST` environment variables either using `.env` files or `export`s.

## CI/CD

An example [GitHub workflow](https://github.com/panther-labs/pypanther-starter-kit/blob/main/.github/workflows/upload.yml) is provided to upload your configured ruleset to your Panther instance when PRs are merged to `release` branch.  `API_HOST` and `API_TOKEN` must be configured in your GitHub repository secrets.

An example process might look like this:

- PRs are merged to `main` as new rules are developed and existing rules are tuned.

- When you are ready to update your Panther instance, create a PR from `main` to `release`.

- Merging the PR to `release` automatically updates Panther, making the `release` branch the single source of truth for your Panther configuration!

## License

This project is licensed under the [AGPL-3.0 License] - see the LICENSE.txt file for details.
