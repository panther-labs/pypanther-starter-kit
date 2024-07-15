from pypanther import PantherSeverity, register, get_panther_rules, PantherLogType

from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_account_discovery import AWSCloudTrailAccountDiscovery
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_stopped import AWSCloudTrailStopped
from pypanther.rules.aws_cloudtrail_rules.aws_console_root_login import AWSConsoleRootLogin

from helpers.cloud import title_root_logins


def overrides():
    # Set AccountDiscovery severity to low
    AWSCloudTrailAccountDiscovery.Severity = PantherSeverity.Low

    # Add custom runbook and reports to CloudTrail stopped
    AWSCloudTrailStopped.override(
        Runbook=(
            "If the account is in production, investigate why CloudTrail was stopped. "
            "If it was intentional, ensure that the account is monitored by another CloudTrail. "
            "If it was not intentional, investigate the account for unauthorized access."
        ),
        Reports=AWSCloudTrailStopped.Reports | {"Internal": ["C.4"]},
    )

    # Get all high severity CloudTrail rules
    high_sev_cloudtrail = get_panther_rules(LogTypes=PantherLogType.AWS_CloudTrail)

    # Override a title dynamic function to match internal cloud account account mappings
    # Check out helpers/cloud.py for the account_lookup_by_id function
    AWSConsoleRootLogin.title = title_root_logins

    register(
        [
            AWSCloudTrailStopped,
            AWSCloudTrailAccountDiscovery,
            *high_sev_cloudtrail,
        ]
    )
