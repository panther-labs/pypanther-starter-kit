from pypanther import get_panther_rules, get_rules, register

from content import rules

# Load base rules
panther_rules = get_panther_rules()
register(panther_rules)

# Load all local custom rules
custom_rules = get_rules(module=rules)
register(custom_rules)
