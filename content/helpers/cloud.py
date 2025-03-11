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


def prod_account_filter(event):
    return event.get("recipientAccountId") in prod_account_ids


# Pre-calculates a set of IDs to be used in overrides and filters
prod_account_ids = {account["accountID"] for account in CLOUD_ACCOUNTS["Production"]}
dev_accounts_ids = {account["accountID"] for account in CLOUD_ACCOUNTS["Development"]}
test_accounts_ids = {account["accountID"] for account in CLOUD_ACCOUNTS["Test"]}
