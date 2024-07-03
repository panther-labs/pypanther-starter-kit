from pypanther import PantherLogType, PantherSeverity, get_panther_rules, register
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_account_discovery import AWSCloudTrailAccountDiscovery
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_stopped import AWSCloudTrailStopped
from pypanther.rules.aws_cloudtrail_rules.aws_codebuild_made_public import AWSCloudTrailCodebuildProjectMadePublic
from pypanther.rules.aws_cloudtrail_rules.aws_console_login_without_mfa import AWSConsoleLoginWithoutMFA
from pypanther.rules.aws_cloudtrail_rules.aws_console_login_without_saml import AWSConsoleLoginWithoutSAML
from pypanther.wrap import exclude, include

from rules.aws_cloudtrail_rules.my_first_custom_rule import MyFirstCustomRule
from rules.aws_cloudtrail_rules.my_first_tuned_rule import MyFirstTunedRule

########################################################
## Variables

onboarded_log_types = [
    # replace with your log types
    PantherLogType.AWS_CloudTrail,
]

AWS_ACCOUNTS = {
    "prod": [
        {"accountID": "123456789012", "accountName": "MyProdAccount"},
    ]
}

########################################################
## Overrides

AWSCloudTrailAccountDiscovery.Severity = PantherSeverity.High
AWSCloudTrailCodebuildProjectMadePublic.DedupPeriodMinutes = 10

AWSCloudTrailStopped.override(
    Runbook="https://runbook.com/AWSCloudTrailStopped",
    Reports=AWSCloudTrailStopped.Reports | {"reporting": ["for", "duty", "sir"]},
)

for rule in get_panther_rules(LogTypes=onboarded_log_types, Severity=PantherSeverity.Critical):
    rule.Tags.append("Critical")

########################################################
## Filters

def is_prod_account(event):
    return event.get("accountID") in ["123456789012"]

include(is_prod_account)(AWSCloudTrailStopped)

include(lambda e: e.get("eventType") == "AwsConsoleSignIn")(AWSConsoleLoginWithoutSAML)
exclude(lambda e: e.get("awsRegion") == "us-east-2")(AWSConsoleLoginWithoutMFA)

########################################################
## Register

register(
    get_panther_rules(
        LogTypes=onboarded_log_types,
    )
)

register(
    [
        MyFirstCustomRule,
        MyFirstTunedRule,
    ]
)
