# pypanther-starter-kit

Detection-As-Code V2 examples and starter kit.

## Getting Started

To get started with this project, you'll need to clone the repository, install the necessary dependencies, and then run tests to ensure everything is set up correctly.

### Prerequisites

Before you begin, make sure you have the following installed:
- Git
- Make
- Python (check the `pyproject.toml` file for the required version)

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

## License

This project is licensed under the [AGPL-3.0 License] - see the LICENSE.txt file for details.
