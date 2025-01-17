# pypanther-starter-kit

`pypanther` is a Python-native detection framework designed to reduce the overhead of rule management, ensure smooth integration with CI/CD workflows, and enhance the effectiveness and actionability of alerts. It is both a library and a CLI, acting as the evolution to our `panther-analysis` and `panther_analysis_tool` repositories.

`pypanther` streamlines how security teams create, customize, and manage detection rules as code:
- Stay up-to-date with upstream rule content without a forked repo
- Flexibly select desired rules based on security use cases
- Modify Panther-managed rules with overrides, filters, and inheritance
- Rapidly build, tune, and test custom rules

*Read our [full documentation](https://docs.panther.com/detections/pypanther) to learn about all features of the framework!*

If you are not yet a Panther user, please reach out to us to [get a demo](https://panther.com/product/request-a-demo/)!

The starer kit serves as a bootstrap for the `pypanther` framework, providing a folder structure and essential components to accelerate the rule development process. **All Panther-managed content lives in the `pypanther` Python package,** so it is not required to maintain a repository fork.

## Example

Here's an example `main.py` getting all GitHub rules, setting overrides, adding a filter, and registering:

```python
from pypanther import get_panther_rules, register, LogType, Severity
from pypanther.rules.github import GitHubActionFailed

# Get all built-in GitHub Audit rules
git_rules = get_panther_rules(log_types=[LogType.GITHUB_AUDIT])

# Override the default rule values to enable and increase the deduplication window
GitHubActionFailed.override(
    enabled=True, dedup_period_minutes=60*8,
)

# Add a tag along the default tags
GitHubActionFailed.extend(
    tags=["CorpSec"],
)

# Set a required configuration on the rule for higher accuracy
GitHubActionFailed.MONITORED_ACTIONS = {
    "main_app": ["code_scanning"],
}

# Write a new filter function to check for bot activity
def github_is_bot_filter(event):
    return bool(event.get("actor_is_bot"))

# Add the filter to all git_rules to exclude bot activity
for rule in git_rules:
    rule.extend(exclude_filters=[is_bot])

# Register and enable rules to be uploaded and tested
register(git_rules)
```

## Getting Started

Clone the repo, install dependencies, and then run tests to ensure everything is set up correctly.

### Prerequisites

Before you begin, make sure you have the following installed:

- **Brew**: Install [Homebrew](https://brew.sh/) if you are on macOS.
- **Git**: Validate Git is installed by running the following command:
    ```bash
    git --version
    ```
    If Git is not installed, you can download it from the [official website](https://git-scm.com/) or install it using a package manager like Homebrew on macOS:
    ```bash
    brew install git
    ```
- **Make**: Install [Make](https://formulae.brew.sh/formula/make) if you don't have it. This project uses a [Makefile](./Makefile) for workflows.
- **Python**: We recommend using [Pyenv](https://github.com/pyenv/pyenv) for managing Python versions and uninstalling other Python versions to avoid conflicts. You can verify your current active Python configuration with:
    ```bash
    which python
    ```
    After installing Pyenv, you can set your python version by running the following:
    ```bash
    pyenv install 3.11
    pyenv global 3.11
    ```
- **Poetry**: Install Poetry version 1.8.0 and ensure it uses the correct Python version with `poetry env use path/to/python3.11`. Follow the [installation guide](https://python-poetry.org/docs/) and use [pipx](https://pipx.pypa.io/stable/installation/). The starter kit includes a pre-configured [pyproject.toml](./pyproject.toml). Run all Python commands inside the Poetry shell, including in your CI pipeline. More details [here](https://python-poetry.org/docs/basic-usage/#using-your-virtual-environment).

### Starter Kit Setup

Follow these steps to configure your local development environment:

1. **Clone the repo**
    ```bash
    git clone git@github.com:panther-labs/pypanther-starter-kit.git
    cd pypanther-starter-kit
    ```

2. **Install dependencies and set up environment**

    ```bash
    make install
    ```

3. **Validate installation**

    ```bash
    make test
    ```

    *Note: When developing and running tests, prefix commands with `poetry run ...`*

### `pypanther` CLI

The `pypanther` CLI is a command-line tool designed to build, test, and upload to a Panther instance. Below are the available commands:

- **version**: Display the current version of the `pypanther` CLI.
- **list**: List managed or registered content.
    ```bash
    pypanther list rules --log-types AWS.CloudTrail --attributes id enabled tags
    ```
- **get**: Retrieve the source code of a specific rule ID including any applied overrides.
    ```bash
    pypanther get rule <id>
    ```
- **test**: Run tests on all your rules, providing a summary of results.
    ```bash
    pypanther test --tags Exfiltration
    ```
- **upload**: Upload your rules to Panther.
    ```bash
    pypanther upload --verbose --output json
    ```

Use `pypanther <command> --help` for more details on each command.

## Trying PyPanther

### Supported Content Types

`pypanther` is under active development (available in closed beta for select customers) and currently supports the following analysis types:

| Analysis Type       | Supported           |
|---------------------|---------------------|
| Streaming Rules     | :white_check_mark:  |
| Data Models         | :white_check_mark:  |
| Helper Functions    | :white_check_mark:  |
| Built-in Content    | :white_check_mark:  |
| Scheduled Rules     | :construction:      |
| Lookups/Enrichments | :construction:      |
| Saved Queries       | :construction:      |
| Policies            | :construction:      |
| Correlation Rules   | :construction:      |

*Note: `packs` have been replaced by the `main.py` and the `get_panther_rules` function.*

As more analysis types are supported, you can declare and upload using `pypanther` with the following guidance:
1. Make sure you are on the latest `pypanther-starter-kit` and `pypanther` library by running `make update`
2. Customize your `main.py` to include panther-managed rules or custom rules. When testing, we recommend starting with only 3-5 rules.
3. Use `pypanther upload` to validate alerts are firing and other content is as you expect it.

`pypanther` content mirrors `panther-analysis` with the addition of a `-prototype` suffix. You can use this to distinguish between v1 and v2 rules. Once `pypanther` is generally available, we will publish our migration tool and guidance to make the cutover as smooth as possible!

### Required File Structure

`pypanther`'s primary configuration file `main.py` must be located in the root directory, and all content is organized into several key directories under the `content/` folder:

- **`main.py`**: This is the main file of the repository. It controls the entire configuration for `pypanther`. The `main.py` file orchestrates which rules are imported and overridden with custom configurations.

- **`content/rules/`**: This directory contains customer-defined rules that are grouped by log type family. Each folder may also include longer sample events for `RuleTest`s.

- **`content/helpers/`**: The `helpers/` directory is home to generic helper functions. These functions are designed to be reusable and can be utilized either in rules or filters. Their purpose is to simplify the code in the main logic by abstracting common tasks into functions.

- **`content/overrides/`**: The `overrides/` directory is dedicated for managing your overrides to built-in rules. We recommend defining new rule override functions (like title or severity), attribute overrides (like include_filters), and mass-updates using for loops using the `apply_overrides()` function. Check the `content/rules` folder for an example.

### Setting Your Configuration

The `main.py` (and all other content in this repository) serves as examples to build your configuration. Read the [full documentation](https://docs.panther.com/detections/pypanther) to learn all of the paradigms.

To interact with your Panther instance via `pypanther upload`, you'll need to set the `PANTHER_API_TOKEN` and `PANTHER_API_HOST` environment variables either using `.env` files or `export`s.

## CI/CD

An example [GitHub workflow](https://github.com/panther-labs/pypanther-starter-kit/blob/main/.github/workflows/upload.yml) is provided to upload your configured ruleset to your Panther instance when PRs are merged to `release` branch.  `API_HOST` and `API_TOKEN` must be configured in your GitHub repository secrets.

An example process might look like this:

- PRs are merged to `main` as new rules are developed and existing rules are tuned.

- When you are ready to update your Panther instance, create a PR from `main` to `release`.

- Merging the PR to `release` automatically updates Panther, making the `release` branch the single source of truth for your Panther configuration!

## License

This project is licensed under the [Apache 2.0 License] - see the LICENSE.txt file for details.
