from pypanther.base import PantherEvent

# The mapping of Cloud account environments, IDs, and names.
CLOUD_ACCOUNTS = {
    "Production": [
        # Change these values to apply to your environment
        {"accountID": "988776655444", "accountName": "Blue"},
        {"accountID": "444556677788", "accountName": "Red"},
    ],
    "Development": [
        # {"accountID": "111111111111", "accountName": "MyDevAccount"},
    ],
    "Test": [
        # {"accountID": "987654321098", "accountName": "MyTestAccount"},
    ],
}


def account_lookup_by_id(account_id):
    for _, accounts in CLOUD_ACCOUNTS.items():
        for account in accounts:
            if str(account_id) == account["accountID"]:
                return account
    return "Account ID not found in lookup. Please update helpers.CLOUD_ACCOUNTS"


def update_account_id_tests(rules):
    sample_account_id = (
        list(prod_account_ids)[0]
        if prod_account_ids
        else list(dev_accounts_ids)[0]
        if dev_accounts_ids
        else list(test_accounts_ids)[0]
        if test_accounts_ids
        else "123456789012"
    )
    for rule in rules:
        for test in rule.Tests:
            test.Log["recipientAccountId"] = sample_account_id


# Pre-calculates a set of IDs to be used in overrides and filters
prod_account_ids = {account["accountID"] for account in CLOUD_ACCOUNTS["Production"]}
dev_accounts_ids = {account["accountID"] for account in CLOUD_ACCOUNTS["Development"]}
test_accounts_ids = {account["accountID"] for account in CLOUD_ACCOUNTS["Test"]}

# Title function overrides


def title_root_logins(_, event: PantherEvent):
    """
    Generates a dynamic alert title for root logins using account mappings.
    Args:
        _ (self): The PantherRule instance (unused)
        event (dict): The CloudTrail event
    """
    ip_address = event.get("sourceIPAddress")
    account = account_lookup_by_id(event.get("recipientAccountId"))
    return f"Root Login from [{ip_address}] in account [{account}]"
