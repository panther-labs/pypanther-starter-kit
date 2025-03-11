from pypanther import get_panther_rules, get_rules, register

from content import rules

# Load all Panther rules
# panther_rules = get_panther_rules()
# register(panther_rules)

# Load custom rules and overrides
custom_rules = get_rules(module=rules)
register(custom_rules)
