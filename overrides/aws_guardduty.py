from pypanther import LogType
from pypanther.wrap import exclude, include

sensitive_aws_ervices = {"s3", "dynamodb", "iam", "secretsmanager", "ec2"}


def guard_duty_sensitive_service_filter(event):
    """Uses GuardDuty findings to check if the event is for a sensitive service."""
    service_name = event.deep_get("service", "action", "awsApiCallAction", "serviceName")
    return any(service_name.startswith(service) for service in sensitive_aws_ervices)


def guard_duty_discovery_filter(event):
    """Uses GuardDuty findings to check if the finding starts with Discovery."""
    return event.get("type").startswith("Discovery")


def apply_overrides(rules):
    for rule in rules:
        if LogType.AWS_GUARDDUTY in rule.log_types:
            exclude(guard_duty_discovery_filter)(rule)
            include(guard_duty_sensitive_service_filter)(rule)
