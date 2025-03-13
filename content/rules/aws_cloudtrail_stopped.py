from pypanther import Severity
from pypanther.rules.aws_cloudtrail import AWSCloudTrailStopped

from content.helpers.cloud import prod_account_filter

# .override() is used to set multiple attributes at once in a panther-managed rule.
AWSCloudTrailStopped.override(
    id="AWS.CloudTrailStopped.Prod",
    default_severity=Severity.HIGH,
    default_runbook=(
        "If the account is in production, investigate why CloudTrail was stopped. "
        "If it was intentional, ensure that the account is monitored by another CloudTrail. "
        "If it was not intentional, investigate the account for unauthorized access."
    ),
    include_filters=[prod_account_filter],
)
