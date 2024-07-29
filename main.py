from pypanther import LogType, Severity

import rules
from overrides import aws_cloudtrail, aws_guardduty
from rule_manager import RuleManager
from rules.panther_audit.validate_rule import PantherAuditUploadArtifacts

# Setup Manager and load rules
manager = RuleManager()
manager.load_managed_rules(
    log_types=[
        LogType.AWS_CLOUDTRAIL,
        LogType.AWS_GUARDDUTY,
        LogType.OKTA_SYSTEM_LOG,
        LogType.GITHUB_AUDIT,
        LogType.PANTHER_AUDIT,
    ],
    default_severity=[
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ],
)
# Load all local custom rules
manager.load_custom_rules(module=rules)

# Set a required field through a direct import
PantherAuditUploadArtifacts.allowed_users = ["PAT Upload"]

# Apply overrides
manager.apply_overrides(aws_cloudtrail)
manager.apply_overrides(aws_guardduty)

# Register all Rules
manager.register_all()
