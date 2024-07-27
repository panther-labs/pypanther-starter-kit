from pypanther import LogType, Severity, get_panther_rules, get_rules, register
from pypanther.display import print_rule_table
from pypanther.registry import registered_rules
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_account_discovery import AWSCloudTrailAccountDiscovery
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_stopped import AWSCloudTrailStopped
from pypanther.rules.aws_cloudtrail_rules.aws_console_root_login import AWSConsoleRootLogin
from pypanther.wrap import exclude, include

import rules
from filters.filters import prod_account_filter, root_login_account_title, guard_duty_sensitive_service_filter
from helpers.cloud import update_account_id_tests
from helpers.rule_overrides import get_rule_by_id

## Get Rules

# Load Panther-managed rules
onboarded_log_types = [
    LogType.AWS_CLOUDTRAIL,
    LogType.AWS_GUARDDUTY,
    LogType.OKTA_SYSTEM_LOG,
    LogType.GITHUB_AUDIT,
]
base_rules = get_panther_rules(log_types=onboarded_log_types)

# Load rules from the `rules/` folder
local_rules = get_rules(module=rules)



## Set Overrides

# Override a set of rule attributes and attach the 'prod_account' filter from above
include(prod_account_filter)(AWSCloudTrailStopped)
# TODO(panther) This is a temporary workaround for updating AWS account IDs in rule tests
update_account_id_tests([AWSCloudTrailStopped])

# Override multiple attributes using the rule override() method
AWSCloudTrailStopped.override(
    default_runbook=(
        "If the account is in production, investigate why CloudTrail was stopped. "
        "If it was intentional, ensure that the account is monitored by another CloudTrail. "
        "If it was not intentional, investigate the account for unauthorized access."
    ),
    reports=AWSCloudTrailStopped.reports | {"Internal": ["C.4"]},
)

# Override a title dynamic function to match internal cloud account account mappings
# Check out helpers/cloud.py for the account_lookup_by_id function
AWSConsoleRootLogin.title = root_login_account_title

# Add two filters to all GuardDuty rules
for rule in base_rules:
    if LogType.AWS_GUARDDUTY in rule.log_types:
        # Include only production accounts
        include(guard_duty_sensitive_service_filter)(rule)
        # Exclude any 'Discovery' tactic finding
        exclude(lambda event: event.get("type").startswith("Discovery"))(rule)

# Example using a rule with validate
validate_rule_example = get_rule_by_id(local_rules, "Custom.Validate.MyRule")
validate_rule_example.allowed_domains = ["example.com"]



## Register Rules

# Register the rules for onboarded log types
register(base_rules)

# Register all custom rules inside the `rules` module
register(local_rules)

# Register rules with overrides
register([AWSCloudTrailStopped, AWSConsoleRootLogin])
