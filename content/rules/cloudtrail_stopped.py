from pypanther import Severity, RuleTest
from pypanther.rules.aws_cloudtrail import AWSCloudTrailStopped, AWSConsoleRootLogin

from content.helpers.cloud import account_lookup_by_id, prod_account_ids

def prod_account_filter(event):
    return event.get("recipientAccountId") in prod_account_ids


class CloudTrailStopped(AWSCloudTrailStopped):
    default_severity = Severity.LOW
    default_runbook = (
        "If the account is in production, investigate why CloudTrail was stopped. "
        "If it was intentional, ensure that the account is monitored by another CloudTrail. "
        "If it was not intentional, investigate the account for unauthorized access."
    )
    include_filters = [prod_account_filter]


class CloudTrailRootLogin(AWSConsoleRootLogin):
    include_filters = [prod_account_filter]

    def title(self, event):
        ip_address = event.get("sourceIPAddress")
        account = account_lookup_by_id(event.get("recipientAccountId"))
        return f"Root Login from [{ip_address}] in account [{account['accountName']}]"

    tests = [
        RuleTest(
            name="Root Login from 136.90.223.255 in account [988776655444]",
            expected_title="Root Login from [136.90.223.255] in account [Blue]",
            expected_result=True,
            log={
                "eventVersion": "1.05",
                "userIdentity": {
                    "type": "Root",
                    "principalId": "1111",
                    "arn": "arn:aws:iam::988776655444:root",
                    "accountId": "988776655444",
                    "userName": "root",
                },
                "eventTime": "2019-01-01T00:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "136.90.223.255",
                "userAgent": "Mozilla",
                "requestParameters": None,
                "responseElements": {"ConsoleLogin": "Success"},
                "additionalEventData": {
                    "LoginTo": "https://console.aws.amazon.com/console/",
                    "MobileVersion": "No",
                    "MFAUsed": "No",
                },
                "eventID": "1",
                "eventType": "AwsConsoleSignIn",
                "recipientAccountId": "988776655444",
            },
        )
    ]
