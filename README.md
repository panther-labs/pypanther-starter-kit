# PyPanther Starter Kit

`pypanther` is a modern Python-based detection framework that empowers security teams to build, test, and manage detection rules as code. It combines the power of a library with the convenience of a CLI, making it easier than ever to create and maintain high-quality security detections.

### 🚀 Key Features

- **Simplified Rule Management**: Create and maintain detection rules in Python with built-in testing and validation
- **CI/CD Integration**: Seamlessly integrate detections into your development workflow
- **Enhanced Alerts**: Generate actionable alerts with rich context and flexible formatting
- **Rule Customization**: Easily modify and extend existing rules with inheritance and overrides
- **Upstream Updates**: Stay current with the latest detection content without maintaining a fork

`pypanther` is the evolution of Panther's `panther-analysis` and `panther_analysis_tool` repositories, bringing modern Python practices to detection engineering.

### 📚 Quick Links

- [Full Documentation](https://docs.panther.com/detections/pypanther)
- [Request a Demo of Panther](https://panther.com/product/request-a-demo/)

## 🏗️ Project Structure

The starter kit serves as a bootstrap for the `pypanther` framework, providing a folder structure and essential components to accelerate the rule development process. **All Panther-managed content lives in the `pypanther` Python package,** so it is not required to maintain a repository fork.

### Directory Layout

```
pypanther-starter-kit/
├── main.py                 # Main configuration file
├── content/
│   ├── rules/             # Customer-defined rules by log type
│   ├── helpers/           # Reusable helper functions
│   └── overrides/         # Rule overrides and customizations
├── pyproject.toml         # Poetry dependencies
└── Makefile              # Development workflows
```

## 💡 Example Usage

Here's an example `main.py` getting all GitHub rules, setting overrides, adding a filter, and registering:

```python
from pypanther import get_panther_rules, register, LogType, Severity
from pypanther.rules.github import GitHubActionFailed

# Get all built-in GitHub Audit rules
git_rules = get_panther_rules(log_types=[LogType.GITHUB_AUDIT])

# Override the default rule values to enable and increase the deduplication window
GitHubActionFailed.override(enabled=True, dedup_period_minutes=60*8,
)

# Add a tag along the default tags
GitHubActionFailed.extend(tags=["CorpSec"],
)

# Set a required configuration on the rule for higher accuracy
GitHubActionFailed.MONITORED_ACTIONS = {"main_app": ["code_scanning"],
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

## 🛠️ Getting Started

### Prerequisites

Before you begin, make sure you have the following installed:

- **Brew**: Install [Homebrew](https://brew.sh/) if you are on macOS
- **Git**: Validate Git is installed:
    ```bash
    git --version
    ```
    If not installed, download from [git-scm.com](https://git-scm.com/) or use Homebrew:
    ```bash
    brew install git
    ```
- **Make**: Install [Make](https://formulae.brew.sh/formula/make) for workflow automation
- **Python**: We recommend using [Pyenv](https://github.com/pyenv/pyenv) for version management:
    ```bash
    pyenv install 3.11
    pyenv global 3.11
    ```
- **Poetry**: Install Poetry via [pipx](https://pipx.pypa.io/stable/installation/):
    ```bash
    pipx install poetry
    poetry env use path/to/python3.11
    ```

### Quick Start

1. **Clone and enter the repo**
    ```bash
    git clone git@github.com:panther-labs/pypanther-starter-kit.git
    cd pypanther-starter-kit
    ```

2. **Install dependencies**
    ```bash
    make install
    ```

3. **Run tests**
    ```bash
    make test
    ```

*Note: When developing and running tests, prefix commands with `poetry run ...`*

## 🔧 CLI Commands

The `pypanther` CLI provides essential tools for development:

| Command | Description | Example |
|---------|-------------|---------|
| `version` | Display CLI version | `pypanther version` |
| `list` | List managed content | `pypanther list rules --log-types AWS.CloudTrail` |
| `get` | Retrieve rule source | `pypanther get rule <id>` |
| `test` | Run rule tests | `pypanther test --tags Exfiltration` |
| `upload` | Upload to Panther | `pypanther upload --verbose` |

Use `pypanther <command> --help` for detailed usage.

## 📝 CLI Examples

### Listing Rules
List all Slack audit log rules with HIGH severity:
```bash
poetry run pypanther list rules --log-types Slack.AuditLogs --default-severity HIGH
```
```
+----------------------------------------------------+-----------------+------------------+---------+
|                         id                         |    log_types    | default_severity | enabled |
+----------------------------------------------------+-----------------+------------------+---------+
|       Slack.AuditLogs.DLPModified-prototype        | Slack.AuditLogs |       HIGH       |   True  |
|     Slack.AuditLogs.EKMConfigChanged-prototype     | Slack.AuditLogs |       HIGH       |   True  |
|  Slack.AuditLogs.EKMSlackbotUnenrolled-prototype   | Slack.AuditLogs |       HIGH       |   True  |
| Slack.AuditLogs.IDPConfigurationChanged-prototype  | Slack.AuditLogs |       HIGH       |   True  |
| Slack.AuditLogs.LegalHoldPolicyModified-prototype  | Slack.AuditLogs |       HIGH       |   True  |
|    Slack.AuditLogs.MFASettingsChanged-prototype    | Slack.AuditLogs |       HIGH       |   True  |
| Slack.AuditLogs.PrivateChannelMadePublic-prototype | Slack.AuditLogs |       HIGH       |   True  |
|    Slack.AuditLogs.SSOSettingsChanged-prototype    | Slack.AuditLogs |       HIGH       |   True  |
| Slack.AuditLogs.UserPrivilegeEscalation-prototype  | Slack.AuditLogs |       HIGH       |   True  |
+----------------------------------------------------+-----------------+------------------+---------+
Total rules: 9
```

### Inspecting Rules
View the source code and configuration of a specific rule:
```bash
poetry run pypanther get rule Slack.AuditLogs.MFASettingsChanged-prototype
```
```
class SlackAuditLogsMFASettingsChanged:
    create_alert = True
    dedup_period_minutes = 60
    display_name = Slack MFA Settings Changed
    enabled = True
    log_types = ['Slack.AuditLogs']
    id = Slack.AuditLogs.MFASettingsChanged-prototype
    summary_attributes = ['p_any_ip_addresses', 'p_any_emails']
    threshold = 1
    tags = ['Slack', 'Defense Evasion', 'Modify Authentication Process', 'Multi-Factor Authentication']
    reports = {'MITRE ATT&CK': ['TA0005:T1556.006']}
    default_severity = HIGH
    default_description = Detects changes to Multi-Factor Authentication requirements
    default_destinations = None
    default_reference = https://slack.com/intl/en-gb/help/articles/204509068-Set-up-two-factor-authentication
    rule = 
    def rule(self, event):
        return event.get("action") == "pref.two_factor_auth_changed"
    ...
```

### Testing Rules
Run tests on a specific rule with detailed output:
```bash
poetry run pypanther test --verbose --id AWS.ALB.HighVol400s
```
```
AWS.ALB.HighVol400s:
   PASS: ELB 400s, no domain
   PASS: ELB 400s, with a domain
     - Title: High volume of web port 4xx errors to [example.com] in account [112233445566]
     - Alert context: {'elb': 'app/web/22222f55555e618c', 'actionsExecuted': ['forward'], 'source_ip': None, 'target_port': 80, 'elb_status_code': 429, 'target_status_code': 429, 'user_agent': None, 'request_url': 'https://ec2-55-22-444-111.us-east-1.compute.amazonaws.com:443/pagekit/index.php', 'mitre_technique': 'Endpoint Denial of Service', 'mitre_tactic': 'Impact'}
   PASS: ELB 200s, with a domain

Test Summary:
   Skipped rules:   0 
   Passed rules:    1 
   Failed rules:    0 
   Total rules:     1

   Passed tests:    3
   Failed tests:    0
   Total tests:     3
```

### Uploading Rules
Upload rules to your Panther instance:
```bash
poetry run pypanther upload --api-token <TOKEN> --api-host https://<API-ENDPOINT>.execute-api.<REGION>.amazonaws.com/v1/public/graphql
```

## 📊 Supported Features

| Feature | Status |
|---------|---------|
| Streaming Rules | ✅ |
| Data Models | ✅ |
| Helper Functions | ✅ |
| Built-in Content | ✅ |
| Manage Custom Schemas | ✅ |
| Scheduled Rules | 🚧 |
| Lookups/Enrichments | 🚧 |
| Saved Queries | 🚧 |
| Policies | 🚧 |
| Correlation Rules | 🚧 |

*Note: `packs` have been replaced by `main.py` and `get_panther_rules`.*

## 🔄 CI/CD Workflows

An example [GitHub workflow](.github/workflows/upload.yml) is provided for automated deployments:

1. Develop and test rules in `main` branch
2. Create PR from `main` to `release` when ready to deploy
3. Merge to `release` to automatically update Panther

Configure `API_HOST` and `API_TOKEN` in your GitHub repository secrets.

## 📄 License

This project is licensed under the [Apache 2.0 License](LICENSE.txt).
