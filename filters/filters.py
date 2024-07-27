from helpers.cloud import prod_account_ids, account_lookup_by_id


def prod_account_filter(event):
    """
    Uses CloudTrail events to check if an account ID is in the list of production accounts.
    This uses a variable from the helpers/cloud module.
    """
    # TODO() Change this to use event.udm('account_id')
    return event.get("recipientAccountId") in prod_account_ids


sensitive_services = {"s3", "dynamodb", "iam", "secretsmanager", "ec2"}


def guard_duty_sensitive_service_filter(event):
    """Uses GuardDuty findings to check if the event is for a sensitive service."""
    service_name = event.deep_get("service", "action", "awsApiCallAction", "serviceName")
    return any(service_name.startswith(service) for service in sensitive_services)


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
