from pypanther import PantherLogType, PantherSeverity, get_panther_rules, register
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_account_discovery import (
    AWSCloudTrailAccountDiscovery,
)
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_stopped import (
    AWSCloudTrailStopped,
)
from pypanther.rules.aws_cloudtrail_rules.aws_codebuild_made_public import (
    AWSCloudTrailCodebuildProjectMadePublic,
)

from rules.my_first_custom_rule import MyFirstCustomRule

########################################################
# define all variables in one section

onboarded_log_types = [
    # replace with your log types
    PantherLogType.AWS_CloudTrail,
]

########################################################
# write all your overrides in one section

AWSCloudTrailAccountDiscovery.Severity = PantherSeverity.High
AWSCloudTrailCodebuildProjectMadePublic.DedupPeriodMinutes = 10

AWSCloudTrailStopped.override(
    Runbook="https://runbook.com/AWSCloudTrailStopped",
    Reports=AWSCloudTrailStopped.Reports | {"reporting": ["for", "duty", "sir"]},
)

for rule in get_panther_rules(
    LogTypes=onboarded_log_types, Severity=PantherSeverity.Critical
):
    rule.OutputIds.append("Slack #security")

########################################################
# register all rules in the last section

# register tells Panther which rules you want uploaded
# accepts a list of PantherRule's
register(
    # utility function to easily upload Panther provided rules you care about
    # you can filter by any rule attribute
    get_panther_rules(
        LogTypes=onboarded_log_types,
    )
)

# register also accepts individual PantherRule's
register(MyFirstCustomRule)
