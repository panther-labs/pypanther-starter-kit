from pypanther import LogType, RuleTest
from pypanther.rules.aws_guardduty.aws_guardduty_high_sev_findings import AWSGuardDutyHighSeverityFinding

sensitive_aws_services = {"s3", "dynamodb", "iam", "secretsmanager", "ec2"}


def guard_duty_sensitive_service_filter(event):
    """Uses GuardDuty findings to check if the event is for a sensitive service."""
    service_name = event.deep_get("service", "action", "awsApiCallAction", "serviceName")
    return any(service_name.startswith(service) for service in sensitive_aws_services)


def guard_duty_discovery_filter(event):
    """Uses GuardDuty findings to check if the finding starts with Discovery."""
    return event.get("type").startswith("Discovery")


guard_duty_high_sev_test = RuleTest(
    name="UnauthorizedAccess high-sev finding, from dynamodb",
    expected_result=True,
    log={
        "type": "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
        "severity": 8,
        "service": {"action": {"awsApiCallAction": {"serviceName": "iam"}}},
        "title": "Credentials that were created exclusively for an EC2 instance through an Instance launch role are being used from another account within AWS.",
    },
)


def apply_overrides(rules):
    for rule in rules:
        if LogType.AWS_GUARDDUTY in rule.log_types:
            rule.extend(
                exclude_filters=[guard_duty_discovery_filter],
                include_filters=[guard_duty_sensitive_service_filter],
            )
    AWSGuardDutyHighSeverityFinding.tests.append(guard_duty_high_sev_test)
