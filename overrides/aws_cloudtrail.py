from pypanther import Severity
from pypanther.rules.aws_cloudtrail import AWSCloudTrailStopped
from pypanther.rules.aws_cloudtrail import AWSConsoleRootLogin

from helpers.cloud import account_lookup_by_id, prod_account_ids


def root_login_account_title(_, event):
    """
    Generates a dynamic alert title for root logins using account mappings.

    Args:
    ----
        _ (self): The PantherRule instance (unused)
        event (dict): The CloudTrail event

    """
    ip_address = event.get("sourceIPAddress")
    account = account_lookup_by_id(event.get("recipientAccountId"))
    return f"Root Login from [{ip_address}] in account [{account}]"


def prod_account_filter(event):
    """
    Uses CloudTrail events to check if an account ID is in the list of production accounts.
    This uses a variable from the helpers/cloud module.
    """
    # TODO() Change this to use event.udm('account_id')
    return event.get("recipientAccountId") in prod_account_ids


def apply_overrides(rules):
    # Set attribute overrides on a specific rule
    AWSCloudTrailStopped.override(
        default_severity=Severity.LOW,
        default_runbook=(
            "If the account is in production, investigate why CloudTrail was stopped. "
            "If it was intentional, ensure that the account is monitored by another CloudTrail. "
            "If it was not intentional, investigate the account for unauthorized access."
        ),
    )

    # Add an include filter with the prod_account_filter function
    AWSCloudTrailStopped.extend(include_filters=[prod_account_filter])

    # Override a rule's title function
    AWSConsoleRootLogin.title = root_login_account_title
