from pypanther import LogType, get_panther_rules, register, get_rules
from content import rules

panther_audit_rules = get_panther_rules(log_types=[LogType.PANTHER_AUDIT])
for rule in panther_audit_rules:
    rule.create_alert = False
    register(rule)

# Load all local rules
custom_rules = get_rules(module=rules)
register(custom_rules)
