from typing import Any, Dict, Optional

from pypanther import LogType, Rule, get_panther_rules, get_rules, register
from pypanther.wrap import exclude, include


class RuleManager:
    def __init__(self):
        self.rules: Dict[str, Rule] = {}
        self.panther_rules: Dict[str, Rule] = {}
        self.custom_rules: Dict[str, Rule] = {}

    def load_managed_rules(self, **kwargs):
        """Load Panther-managed rules."""
        panther_rules_list = get_panther_rules(**kwargs)
        self.panther_rules = {rule.id: rule for rule in panther_rules_list}
        self.rules.update(self.panther_rules)

    def load_custom_rules(self, module):
        """Load custom rules from a specified module."""
        custom_rules_list = get_rules(module=module)
        self.custom_rules = {rule.id: rule for rule in custom_rules_list}
        self.rules.update(self.custom_rules)

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """Retrieve a rule by its ID."""
        return self.rules.get(rule_id)

    def override(self, rule_id: str, **kwargs):
        """Apply overrides to a specific rule."""
        if rule_id in self.rules:
            self.rules[rule_id].override(**kwargs)
        else:
            print(f"Warning: Rule with id {rule_id} not found.")

    def apply_overrides(self, overrides_module):
        overrides_module.apply_overrides(self)

    def set_title(self, rule_id: str, method: Any):
        self.set_method(rule_id=rule_id, method_name="title", value=method)

    def set_method(self, rule_id: str, method_name: str, value: Any):
        """
        Set a dynamic method for a specific rule (e.g., title, severity, destinations).

        Args:
            rule_id (str): The ID of the rule to modify.
            method_name (str): The name of the method to set (e.g., 'title', 'severity', 'destinations').
            value (Any): The value to set for the method. Can be a function or a static value.

        Raises:
            ValueError: If the rule is not found or the method doesn't exist.
        """
        if rule_id not in self.rules:
            raise ValueError(f"Rule with ID '{rule_id}' not found.")

        rule = self.rules[rule_id]

        if not hasattr(rule, method_name):
            raise ValueError(f"Method '{method_name}' does not exist for rule '{rule_id}'.")

        # If value is callable, set it directly as the method
        if callable(value):
            setattr(rule, method_name, value)
        else:
            # If value is not callable, create a lambda function that returns the value
            setattr(rule, method_name, lambda event: value)

    def include(self, rule_id: str, filter_func):
        """Apply an include filter to a specific rule."""
        if rule_id in self.rules:
            include(filter_func)(self.rules[rule_id])
        else:
            print(f"Warning: Rule with id {rule_id} not found.")

    def exclude(self, rule_id: str, filter_func):
        """Apply an exclude filter to a specific rule."""
        if rule_id in self.rules:
            exclude(filter_func)(self.rules[rule_id])
        else:
            print(f"Warning: Rule with id {rule_id} not found.")

    def include_bulk(self, log_type: LogType, filter_func):
        """Apply a filter to all rules of a specific log type."""
        for rule in self.rules.values():
            if log_type in rule.log_types:
                include(filter_func)(rule)

    def exclude_bulk(self, log_type: LogType, filter_func):
        """Exclude events based on a filter for all rules of a specific log type."""
        for rule in self.rules.values():
            if log_type in rule.log_types:
                exclude(filter_func)(rule)

    def set_property(self, rule_id: str, property_name: str, value: Any):
        """
        Set a specific property for a rule.

        Args:
            rule_id (str): The ID of the rule to modify.
            property_name (str): The name of the property to set.
            value (Any): The value to set for the property.

        Raises:
            ValueError: If the rule is not found or the property doesn't exist.
        """
        if rule_id not in self.rules:
            raise ValueError(f"Rule with ID '{rule_id}' not found.")

        rule = self.rules[rule_id]
        if not hasattr(rule, property_name):
            raise ValueError(f"Property '{property_name}' does not exist for rule '{rule_id}'.")

        setattr(rule, property_name, value)

        # If the rule has a validate_config method, call it
        if hasattr(rule, "validate_config"):
            rule.validate_config()

    def update_rule_tests(self, rule_id: str, update_func):
        """Update tests for a specific rule."""
        if rule_id in self.rules:
            update_func(self.rules[rule_id])
        else:
            print(f"Warning: Rule with id {rule_id} not found.")

    def register_all(self):
        """Register all loaded rules."""
        register(list(self.rules.values()))

    def __len__(self):
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules.values())
