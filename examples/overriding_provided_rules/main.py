from pypanther import PantherLogType, PantherSeverity, get_panther_rules, register
from pypanther.rules.aws_cloudtrail_rules.aws_cloudtrail_created import (
    AWSCloudTrailCreated,
)
from pypanther.rules.box_rules.box_policy_violation import (
    BoxContentWorkflowPolicyViolation,
)

from rules.asana_service_account_created import AsanaServiceAccountCreatedNoBigDeal

######################################################################
# Using python to override a single attribute

AWSCloudTrailCreated.Severity = PantherSeverity.High
register(AWSCloudTrailCreated)

######################################################################
# Using the "override" function for multi-line attribute overrides

BoxContentWorkflowPolicyViolation.override(
    Severity=PantherSeverity.High,
    Runbook="Check if other internal users hit this same violation",
)

# Extend attributes in place
BoxContentWorkflowPolicyViolation.POLICY_VIOLATIONS.add("NEW_VIOLATION")
register(BoxContentWorkflowPolicyViolation)

######################################################################
# Using a rule that overrides a Panther rule

register(AsanaServiceAccountCreatedNoBigDeal)

######################################################################
# Monkey patching a rule function

rules = get_panther_rules(
    Enabled=True,
    Severity=[PantherSeverity.Critical, PantherSeverity.High],
    Tags=["Configuration Required"],
)


# Define the destination override
def cloudtrail_destinations(self, event):
    if event.get("recipientAccountId") == 112233445566:
        # Name or UUID of a configured Slack Destination
        return ["AWS Notifications"]
    # Suppress the alert, doesn't deliver
    return ["SKIP"]


# Appending to the Panther-managed rules' destinations and tags
for rule in rules:
    rule.OutputIds.append("Slack #security-critical")
    rule.Tags.append("Production")

    # updating the destinations for CloudTrail rules
    if PantherLogType.AWS_CloudTrail in rule.LogTypes:
        rule.destinations = cloudtrail_destinations

    # monkey patching methods (what does monkey patching mean)
    original_title = rule.title
    rule.title = lambda _, event: original_title(_, event) + "_Production"
