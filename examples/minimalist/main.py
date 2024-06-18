from pypanther import get_panther_rules, register

# uploads all Panther provided rules
register(get_panther_rules())
