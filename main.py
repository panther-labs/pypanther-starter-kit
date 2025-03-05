from pypanther import LogType, Severity, get_panther_rules, get_rules, register

from content import rules

# Load Panther Audit rules
panther_audit_rules = get_panther_rules(log_types=[LogType.PANTHER_AUDIT])
register(panther_audit_rules)
for rule in panther_audit_rules:
    if rule.id == "Panther.User.Modified-prototype":
        continue
    rule.create_alert = False

# Load AWS rules
aws_rules = get_panther_rules(
    log_types=[
        LogType.AWS_CLOUDTRAIL,
        LogType.AWS_GUARDDUTY,
    ],
    default_severity=[
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
        Severity.LOW,
    ],
    enabled=True,
)
aws_ignore_rule_ids = [
    "AWS.WAF.Disassociation-prototype",
    "AWS.ConfigService.DisabledDeleted-prototype",
    "AWS.IPSet.Modified-prototype",
]
for rule in aws_rules:
    if rule.id.startswith("Standard") or rule.id.startswith("AWS.RDS"):
        continue
    register(rule)

# Load GSuite rules
gsuite_ignore_rule_ids = [
    "GSuite.DocOwnershipTransfer-prototype",
    "Google.Workspace.Apps.New.Mobile.App.Installed-prototype",
]
gsuite_rules = get_panther_rules(log_types=[LogType.GSUITE_ACTIVITY_EVENT])
for rule in gsuite_rules:
    if rule.id in gsuite_ignore_rule_ids:
        continue
    if rule.id == "GSuite.GovernmentBackedAttack-prototype":
        rule.default_severity = Severity.HIGH
    if rule.id == "GSuite.Rule-prototype":
        rule.default_severity = Severity.MEDIUM
    register(rule)

# Load local rules
custom_rules = get_rules(module=rules)
register(custom_rules)
