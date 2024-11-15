from pypanther import Severity
from pypanther.rules.aws_cloudtrail import AWSCloudTrailStopped, AWSConsoleRootLogin

from content.helpers.cloud import account_lookup_by_id, prod_account_ids


class CloudTrailStopped(AWSCloudTrailStopped):
    id = "AWSCloudTrailStopped-CUSTOM"
    include_filters = [lambda event: event.get("recipientAccountId") in prod_account_ids]
    default_severity = Severity.HIGH
    default_runbook = (
        "If the account is in production, investigate why CloudTrail was stopped. "
        "If it was intentional, ensure that the account is monitored by another CloudTrail. "
        "If it was not intentional, investigate the account for unauthorized access."
    )


class RootLogin(AWSConsoleRootLogin):
    id = "AWSRootLogin-CUSTOM"
    default_severity = Severity.HIGH

    def title(_, event):
        ip_address = event.get("sourceIPAddress")
        account = account_lookup_by_id(event.get("recipientAccountId"))
        return f"Root Login from [{ip_address}] in account [{account}]"
