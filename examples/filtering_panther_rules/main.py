from pypanther import PantherLogType, PantherSeverity, get_panther_rules, register

onboarded_log_types = [
    PantherLogType.AWS_ALB,
    PantherLogType.AWS_CloudTrail,
]

# filter out rules you don't care about by skipping them
for rule in get_panther_rules():
    for log_type in rule.LogTypes:
        if log_type not in onboarded_log_types:
            continue

    if rule.Severity <= PantherSeverity.Low:
        continue

    register(rule)


# filter on rule attributes by supplying filter args to get_panther_rules
register(
    get_panther_rules(
        LogTypes=[
            # include rules with AWS_ALB or AWS_CloudTrail log types
            PantherLogType.AWS_ALB,
            PantherLogType.AWS_CloudTrail,
        ],
        Severity=[
            # include rules with Critical or High severity
            PantherSeverity.Critical,
            PantherSeverity.High,
        ],
    )
)
