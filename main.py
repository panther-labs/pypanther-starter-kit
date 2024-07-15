from pypanther import PantherLogType, get_panther_rules, register
from pypanther.wrap import exclude, include
from pypanther.get import table_print
from pypanther.registry import __REGISTRY as registry

from rules.aws_alb_rules.alb_high_400s import AWSALBHighVol400s
from rules.aws_cloudtrail_rules.config import overrides as aws_cloudtrail_overrides
from rules.custom_log_type.ids_rules import HostIDSBaseRule, HostIDSMalware

########################################################
## Importing Panther-managed Rules
##
## get_panther_rules() returns a list of Panther-managed rules.
## Calling without arguments returns everything, and passing
## LogTypes, Severity, Tags, etc, returns based on those attrs.

# Note: Replace with your onboarded log types
onboarded_log_types = [
    PantherLogType.AWS_GuardDuty,
    PantherLogType.Okta_SystemLog,
]
# Get Panther-managed rules for onboarded log types
base_rules = get_panther_rules(LogTypes=onboarded_log_types)

## Get Panther-managed rules for specific severities
# high_sev_rules = get_panther_rules(
#     LogTypes=onboarded_log_types,
#     Severity=[
#         PantherSeverity.Critical,
#         PantherSeverity.High,
#     ],
# )


########################################################
## Overrides (in-line)
##
## Apply your internal configurations to Panther-managed rules.
## This can include single attributes, multiple attributes, or filters.

# Define a filter function to check if the event is for a sensitive service
sensitive_services = {"s3", "dynamodb", "iam", "secretsmanager", "ec2"}


def filter_guardduty_sensitive_service(event):
    """Uses GuardDuty findings to check if the event is for a sensitive service."""
    service_name = event.deep_get("service", "action", "awsApiCallAction", "serviceName")
    return any(service_name.startswith(service) for service in sensitive_services)


# Add two filters to all GuardDuty rules
for rule in base_rules:
    if PantherLogType.AWS_GuardDuty in rule.LogTypes:
        # Include only production accounts
        include(filter_guardduty_sensitive_service)(rule)
        # Exclude any 'Discovery' tactic finding
        exclude(lambda event: event.get("type").startswith("Discovery"))(rule)


########################################################
## Register
##
## Register your rules to upload them to your Panther instance.
## Register also enables tests to be run with `pypanther test`.

register(base_rules)
register(aws_cloudtrail_overrides())

register(
    [
        AWSALBHighVol400s,
        HostIDSBaseRule,
        HostIDSMalware,
    ]
)

# Print the registry
print(table_print(registry))
