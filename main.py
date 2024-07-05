from pypanther import PantherLogType, PantherSeverity, get_panther_rules, register
from pypanther.wrap import exclude, include
from pypanther.get import table_print

from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_account_discovery import AWSCloudTrailAccountDiscovery
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_stopped import AWSCloudTrailStopped
from pypanther.rules.aws_cloudtrail_rules.aws_console_root_login import AWSConsoleRootLogin

from rules.aws_rules.alb_high_400s import AWSALBHighVol400s
from rules.custom_logs.ids_rules import HostIDSBaseRule, HostIDSMalware
from helpers.cloud import prod_account_ids, account_lookup_by_id, update_account_id_tests


########################################################
## Importing Panther-managed Rules
##
## Use get_panther_rules() to return a list of Panther-managed rules.
## Calling without arguments returns everything and passing attributes
## like LogTypes, Severity, or Tags filters rules matching the values.

onboarded_log_types = [
    # Replace with your onboarded log types
    PantherLogType.AWS_CloudTrail,
    PantherLogType.AWS_GuardDuty,
    PantherLogType.Okta_SystemLog,
]

# Get Panther built-in rules for onboarded log types
base_rules = get_panther_rules(LogTypes=onboarded_log_types)

## Get Panther-managed rules with certain severities
# high_sev_rules = get_panther_rules(
#     LogTypes=onboarded_log_types,
#     Severity=[
#         PantherSeverity.Critical,
#         PantherSeverity.High,
#     ],
# )

## Get all Panther-managed Rules
# all_rules = get_panther_rules()


########################################################
## Filter/Dynamic Functions
##
## Add filters to include/exclude events from being evaluated by rules.


def prod_account(event):
    # TODO() Change this to use event.udm('account_id')
    return event.get("recipientAccountId") in prod_account_ids


sensitive_services = {"s3", "dynamodb", "iam", "secretsmanager", "ec2"}


def guard_duty_sensitive_service(event):
    service_name = event.deep_get("service", "action", "awsApiCallAction", "serviceName")
    return any(service_name.startswith(service) for service in sensitive_services)


def root_login_account(_, event):
    ip_address = event.get("sourceIPAddress")
    account = account_lookup_by_id(event.get("recipientAccountId"))
    return f"Root Login from [{ip_address}] in account [{account}]"


########################################################
## Overrides
##
## Apply your custom configurations to Panther-managed rules.
## This can include single or multiple attributes and filters.

# Override a single attribute
AWSCloudTrailAccountDiscovery.Severity = PantherSeverity.Low

# Override a set of rule attributes and attach a filter
include(prod_account)(AWSCloudTrailStopped)
# TODO() Update this temporary workaround
update_account_id_tests([AWSCloudTrailStopped])
# Override multiple atributes at once
AWSCloudTrailStopped.override(
    Runbook=(
        "If the account is in production, investigate why CloudTrail was stopped. "
        "If it was intentional, ensure that the account is monitored by another CloudTrail. "
        "If it was not intentional, investigate the account for unauthorized access."
    ),
    Reports=AWSCloudTrailStopped.Reports | {"Internal": ["C.4"]},
)

# Override a title function to match internal naming conventions
AWSConsoleRootLogin.title = root_login_account

# Add two filters to all GuardDuty rules
for rule in base_rules:
    if PantherLogType.AWS_GuardDuty in rule.LogTypes:
        # Include only production accounts
        include(guard_duty_sensitive_service)(rule)
        # Exclude any 'Discovery' tactic finding
        exclude(lambda event: event.get("type").startswith("Discovery"))(rule)


########################################################
## Register
##
## Register your rules to upload them to your Panther instance.
## Register also enables tests to be run with `pypanther test`.

## Register all rules
# register(all_rules)

# Use table_print() to pretty print the list of rules
print("Base Rules")
print(table_print(base_rules))

# Register the rules for onboarded log types
register(base_rules)

register(
    [
        AWSALBHighVol400s,
        AWSCloudTrailStopped,
        AWSCloudTrailAccountDiscovery,
        AWSConsoleRootLogin,
        HostIDSBaseRule,
        HostIDSMalware,
    ]
)
