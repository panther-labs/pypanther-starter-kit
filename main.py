from pypanther import get_panther_rules, get_rules, register

from content import rules
from content.helpers.custom_log_types import CustomLogType

# Load base rules
panther_rules = get_panther_rules()
register(panther_rules)

# Load all local custom rules
custom_rules = get_rules(module=rules)
register(custom_rules)

# Omit rules with custom log types, since they must be present in the Panther instance for upload to work
# custom_rules = [rule for rule in custom_rules if not any(custom in rule.log_types for custom in CustomLogType)]
