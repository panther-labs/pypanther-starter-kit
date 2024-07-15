from pypanther import PantherSeverity, get_panther_rules, PantherLogType
from pypanther.wrap import include

from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_account_discovery import AWSCloudTrailAccountDiscovery
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_stopped import AWSCloudTrailStopped
from pypanther.rules.aws_cloudtrail_rules.aws_console_root_login import AWSConsoleRootLogin

from helpers.cloud import title_root_logins, update_account_id_tests, filter_prod_account


def overrides():
    # Set AccountDiscovery severity to low
    AWSCloudTrailAccountDiscovery.Severity = PantherSeverity.Low

    # Override a title dynamic function to match internal cloud account account mappings
    # Check out helpers/cloud.py for the account_lookup_by_id function
    AWSConsoleRootLogin.title = title_root_logins

    # Add custom runbook and reports to CloudTrail stopped
    AWSCloudTrailStopped.override(
        Runbook=(
            "If the account is in production, investigate why CloudTrail was stopped. "
            "If it was intentional, ensure that the account is monitored by another CloudTrail. "
            "If it was not intentional, investigate the account for unauthorized access."
        ),
        Reports=AWSCloudTrailStopped.Reports | {"Internal": ["C.4"]},
    )
    # Override a set of rule attributes and attach the 'prod_account' filter from above
    include(filter_prod_account)(AWSCloudTrailStopped)
    # TODO(panther) This is a temproary workaround for updating AWS account IDs in rule tests
    update_account_id_tests([AWSCloudTrailStopped])

    # Get all high severity CloudTrail rules
    high_sev_cloudtrail = get_panther_rules(LogTypes=PantherLogType.AWS_CloudTrail)

    return [
        AWSCloudTrailStopped,
        AWSCloudTrailAccountDiscovery,
        AWSConsoleRootLogin,
        *high_sev_cloudtrail,
    ]
