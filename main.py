from pypanther import LogType, get_panther_rules, register


# Load base rules
register(
    get_panther_rules(
        log_types=[
            LogType.GCP_AUDIT_LOG,
            LogType.GCP_HTTP_LOAD_BALANCER,
            LogType.PANTHER_AUDIT,
            LogType.GSUITE_ACTIVITY_EVENT,
        ],
        # default_severity=[
        #     Severity.CRITICAL,
        #     Severity.HIGH,
        # ],
    )
)

# Load all local custom rules
# custom_rules = get_rules(module=rules)
