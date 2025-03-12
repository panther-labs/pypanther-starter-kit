# PyPanther Starter Kit

`pypanther` is a modern Python-based detection framework that empowers security teams to build, test, and manage detection rules as code. It combines the power of a library with the convenience of a CLI, making it easier than ever to create and maintain high-quality security detections.

### 🚀 Key Features

- **Simple Rule Management**: Maintain detection rules in Python with built-in testing and validation
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

## 💡 Usage

### Overrides (recommended for simple changes):

```python
from pypanther import register
from pypanther.rules.github import GitHubActionFailed

# Simple configuration changes
GitHubActionFailed.override(
    enabled=True,
    dedup_period_minutes=60*8
)

# Adding or modifying attributes
GitHubActionFailed.extend(
    tags=["CorpSec"],
    reference="https://company.docs/github-actions"
)

register(GitHubActionFailed)
```

Best for:
- Simple configuration changes (enabled, severity, dedup period, etc.)
- Adding or modifying attributes (tags, references, descriptions)
- Quick one-off customizations
- Changes that don't require complex logic modifications

### Bulk Changes (recommended for broad configuration updates)

```python
from pypanther import get_panther_rules, register, LogType, Severity

# Get all GitHub Audit rules of Medium/High severity
rules = get_panther_rules(
    log_types=[LogType.GITHUB_AUDIT],
    severity=[Severity.MEDIUM, Severity.HIGH]
)

# Define a filter to exclude bot activity
def github_is_bot_filter(event):
    return bool(event.get("actor_is_bot"))

# Apply the filter to all rules
for rule in rules:
    rule.extend(exclude_filters=[github_is_bot_filter])

# Register the filtered rules
register(rules)
```

Best for:
- Applying filters and configurations across many rules
- Making changes based on log type or severity level
- Batch updates to multiple detection rules

### Using Inheritance (recommended for complex changes):

```python
from pypanther import register
from pypanther.rules.github import GitHubActionFailed

class CustomGitHubActionFailed(GitHubActionFailed):
    """Enhanced GitHub Action failure detection"""
    
    # Override class attributes
    enabled = True
    dedup_period_minutes = 60*8
    
    # Custom constants
    ALLOWED_FAILURES = {"lint", "format"}
    
    # Override the rule logic
    def rule(self, event):
        # First check the parent rule's conditions
        if not super().rule(event):
            return False
            
        # Add custom logic
        action_name = event.get("action_name")
        return action_name not in self.ALLOWED_FAILURES

register(CustomGitHubActionFailed)
```

Best for:
- Complex modifications to rule logic
- Adding new class attributes or methods
- Maintaining multiple variants of a rule
- Rules that need extensive customization
- Reusable rule patterns across your organization

> Note: While both overrides and inheritance can achieve similar results, choose inheritance when you need to maintain and version control your customizations as distinct rule implementations. Use override methods for simpler, configuration-based changes that don't require new logic outside of simple filters.

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

> **Note**: The `pypanther list` and `pypanther get` commands only reflect the state of your local configuration and the pypanther library. They do not show the current state of rules in your Panther instance. To see what changes will be applied to your Panther instance, use the `pypanther upload` command.

## 📝 CLI Examples

### Listing Rules
List all registered Slack audit log rules with HIGH severity:
```bash
$ poetry run pypanther list rules --log-types Slack.AuditLogs --default-severity HIGH

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

List all panther-managed Slack audit log rules:
```bash
poetry run pypanther list rules --log-types Slack.AuditLogs --managed
+----------------------------------------------------------+-----------------+------------------+---------+
|                            id                            |    log_types    | default_severity | enabled |
+----------------------------------------------------------+-----------------+------------------+---------+
|       Slack.AuditLogs.AppAccessExpanded-prototype        | Slack.AuditLogs |      MEDIUM      |   True  |
|            Slack.AuditLogs.AppAdded-prototype            | Slack.AuditLogs |      MEDIUM      |   True  |
|           Slack.AuditLogs.AppRemoved-prototype           | Slack.AuditLogs |      MEDIUM      |   True  |
|         Slack.AuditLogs.ApplicationDoS-prototype         | Slack.AuditLogs |     CRITICAL     |   True  |
|          Slack.AuditLogs.DLPModified-prototype           | Slack.AuditLogs |       HIGH       |   True  |
|        Slack.AuditLogs.EKMConfigChanged-prototype        | Slack.AuditLogs |       HIGH       |   True  |
|     Slack.AuditLogs.EKMSlackbotUnenrolled-prototype      | Slack.AuditLogs |       HIGH       |   True  |
|         Slack.AuditLogs.EKMUnenrolled-prototype          | Slack.AuditLogs |     CRITICAL     |   True  |
|    Slack.AuditLogs.IDPConfigurationChanged-prototype     | Slack.AuditLogs |       HIGH       |   True  |
|   Slack.AuditLogs.InformationBarrierModified-prototype   | Slack.AuditLogs |      MEDIUM      |   True  |
|       Slack.AuditLogs.IntuneMDMDisabled-prototype        | Slack.AuditLogs |     CRITICAL     |   True  |
|    Slack.AuditLogs.LegalHoldPolicyModified-prototype     | Slack.AuditLogs |       HIGH       |   True  |
|       Slack.AuditLogs.MFASettingsChanged-prototype       | Slack.AuditLogs |       HIGH       |   True  |
|           Slack.AuditLogs.OrgCreated-prototype           | Slack.AuditLogs |       LOW        |   True  |
|           Slack.AuditLogs.OrgDeleted-prototype           | Slack.AuditLogs |      MEDIUM      |   True  |
|       Slack.AuditLogs.PassthroughAnomaly-prototype       | Slack.AuditLogs |       LOW        |   True  |
| Slack.AuditLogs.PotentiallyMaliciousFileShared-prototype | Slack.AuditLogs |     CRITICAL     |   True  |
|    Slack.AuditLogs.PrivateChannelMadePublic-prototype    | Slack.AuditLogs |       HIGH       |   True  |
|       Slack.AuditLogs.SSOSettingsChanged-prototype       | Slack.AuditLogs |       HIGH       |   True  |
|    Slack.AuditLogs.ServiceOwnerTransferred-prototype     | Slack.AuditLogs |     CRITICAL     |   True  |
|   Slack.AuditLogs.UserPrivilegeChangedToUser-prototype   | Slack.AuditLogs |      MEDIUM      |   True  |
|    Slack.AuditLogs.UserPrivilegeEscalation-prototype     | Slack.AuditLogs |       HIGH       |   True  |
+----------------------------------------------------------+-----------------+------------------+---------+
Total rules: 22
```

### Inspecting Rules
View the source code and configuration of a specific rule:
```bash
$ poetry run pypanther get rule Slack.AuditLogs.MFASettingsChanged-prototype

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
> **Important**: When writing rules and tests, only use Python libraries that are available in the Panther runtime environment. The following Python libraries are available in addition to those provided by AWS Lambda:
>
> | Package | Version | Description | License |
> |---------|----------|-------------|----------|
> | **jsonpath-ng** | 1.5.2 | JSONPath Implementation | Apache v2 |
> | **policyuniverse** | 1.3.3.20210223 | Parse AWS ARNs and Policies | Apache v2 |
> | **requests** | 2.23.0 | Easy HTTP Requests | Apache v2 |
>
> Additionally, you have access to:
> - Python standard library
> - **boto3** (provided by AWS Lambda)
> - **pypanther** library (version defined in your local Poetry environment)
> - Panther helper functions (as locally defined and using `pypanther`)
>
> Using libraries not listed above in your rules may cause them to fail when deployed to Panther.
>
> For more details, see the [Available Python Libraries documentation](https://docs.panther.com/detections/rules/python#available-python-libraries).

Run tests on a specific rule with detailed output:
```bash
$ poetry run pypanther test --verbose --id AWS.ALB.HighVol400s

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
$ poetry run pypanther upload --api-token <TOKEN> --api-host https://<API-ENDPOINT>.execute-api.<REGION>.amazonaws.com/v1/public/graphql
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