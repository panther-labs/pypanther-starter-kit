from pypanther import PantherSeverity, register, get_panther_rules, PantherLogType

from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_account_discovery import AWSCloudTrailAccountDiscovery
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_stopped import AWSCloudTrailStopped

# Set severity to low
AWSCloudTrailAccountDiscovery.Severity = PantherSeverity.Low

# Add custom runbook and reports
AWSCloudTrailStopped.override(
    Runbook=(
        "If the account is in production, investigate why CloudTrail was stopped. "
        "If it was intentional, ensure that the account is monitored by another CloudTrail. "
        "If it was not intentional, investigate the account for unauthorized access."
    ),
    Reports=AWSCloudTrailStopped.Reports | {"Internal": ["C.4"]},
)

high_sev_cloudtrail = get_panther_rules(PantherLogType.AWS_CloudTrail, Severity=PantherSeverity.High)

register(
    [
        AWSCloudTrailStopped,
        AWSCloudTrailAccountDiscovery,
        *high_sev_cloudtrail,
    ]
)
