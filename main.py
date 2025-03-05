from pypanther import LogType, get_panther_rules, register, get_rules
from content import rules

panther_audit_rules = get_panther_rules(log_types=[LogType.PANTHER_AUDIT])
register(panther_audit_rules)
for rule in panther_audit_rules:
    if rule.id == "Panther.User.Modified-prototype":
        continue
    rule.create_alert = False

# Load all local rules
custom_rules = get_rules(module=rules)
register(custom_rules)
