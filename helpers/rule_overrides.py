def get_rule_by_id(rules, rule_id):
    for rule in rules:
        if rule.id == rule_id:
            return rule
    return None
