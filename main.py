from pypanther import get_panther_rules, get_rules, register
from pypanther.display import print_rule_table
from pypanther.registry import registered_rules

from helpers.custom_log_types import CustomLogType
from overrides import aws_cloudtrail, aws_guardduty
from rules import examples

# Load base rules
base_rules = get_panther_rules(
    # log_types=[
    #     LogType.AWS_CLOUDTRAIL,
    #     LogType.AWS_GUARDDUTY,
    #     LogType.PANTHER_AUDIT,
    # ],
    # default_severity=[
    #     Severity.MEDIUM,
    #     Severity.HIGH,
    # ],
)
# Load all local custom rules
custom_rules = get_rules(module=examples)
# Omit rules with custom log types, since they must be present in the Panther instance for upload to work
custom_rules = [rule for rule in custom_rules if not any(custom in rule.log_types for custom in CustomLogType)]

# Apply overrides
aws_cloudtrail.apply_overrides(base_rules)
aws_guardduty.apply_overrides(base_rules)

# Register all rules
register(base_rules + custom_rules)
print_rule_table(registered_rules())
print("Registered rules:", len(registered_rules()))
