from pypanther import Severity

from helpers.cloud import account_lookup_by_id, prod_account_ids, update_account_id_tests
from rule_manager import RuleManager


def root_login_account_title(_, event):
    """
    Generates a dynamic alert title for root logins using account mappings.
    Args:
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


def apply_overrides(manager: RuleManager):
    # Set attribute overrides on a specific rule
    manager.apply_override(
        "AWS.CloudTrail.Stopped-prototype",
        default_severity=Severity.LOW,
        default_runbook=(
            "If the account is in production, investigate why CloudTrail was stopped. "
            "If it was intentional, ensure that the account is monitored by another CloudTrail. "
            "If it was not intentional, investigate the account for unauthorized access."
        ),
    )
    # Override a rule's title function
    manager.set_rule_method("AWS.Console.RootLogin-prototype", "title", root_login_account_title)

    # Set an include filter for a specific rule
    manager.include("AWS.CloudTrail.Stopped-prototype", prod_account_filter)
    update_account_id_tests([manager.get_rule_by_id("AWS.CloudTrail.Stopped-prototype")])
