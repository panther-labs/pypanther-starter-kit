from pypanther import get_panther_rules, get_rules, register

from rules import examples

# from overrides import aws_cloudtrail, aws_guardduty

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
# TODO: Update when custom rules are functional
custom_rules = get_rules(module=examples)

# Apply overrides
# aws_cloudtrail.apply_overrides(base_rules)
# aws_guardduty.apply_overrides(base_rules)

# Register all rules
register(base_rules + custom_rules)
