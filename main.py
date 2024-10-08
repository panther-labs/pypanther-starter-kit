from pypanther import get_panther_rules, get_rules, register

from content import rules
from content.helpers.custom_log_types import CustomLogType
from content.overrides import aws_cloudtrail, aws_guardduty

# Load base rules
base_rules = get_panther_rules(
    # log_types=[
    #     LogType.AWS_CLOUDTRAIL,
    #     LogType.AWS_GUARDDUTY,
    #     LogType.PANTHER_AUDIT,
    # ],
    # default_severity=[
    #     Severity.CRITICAL,
    #     Severity.HIGH,
    # ],
)
# Load all local custom rules
custom_rules = get_rules(module=rules)
# Omit rules with custom log types, since they must be present in the Panther instance for upload to work
custom_rules = [rule for rule in custom_rules if not any(custom in rule.log_types for custom in CustomLogType)]

# Apply overrides
aws_cloudtrail.apply_overrides(base_rules)
aws_guardduty.apply_overrides(base_rules)

# Register all rules
register(custom_rules)
