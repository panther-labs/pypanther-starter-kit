from pypanther import get_panther_rules, get_rules, register

import rules

# from overrides import aws_cloudtrail, aws_guardduty

# Load base rules
base_rules = get_panther_rules(
    # log_types=[
    #     LogType.AWS_CLOUDTRAIL,
    #     LogType.AWS_GUARDDUTY,
    #     LogType.OKTA_SYSTEM_LOG,
    #     LogType.PANTHER_AUDIT,
    # ],
    # default_severity=[
    #     Severity.MEDIUM,
    #     Severity.HIGH,
    # ],
)
# Load all local custom rules
custom_rules = get_rules(module=rules)

# Set a required rule property with a direct import
# PantherAuditUploadArtifacts.allowed_users = ["PAT Upload"]

# Apply overrides
# aws_cloudtrail.apply_overrides(base_rules)
# aws_guardduty.apply_overrides(base_rules)

# Register all rules
register(base_rules + custom_rules)
