from pypanther import LogType, Rule, RuleTest, Severity
from pypanther.rules.aws_cloudtrail import AWSConsoleRootLogin

from content.helpers.cloud import account_lookup_by_id, prod_account_filter


class CloudTrailRootLoginProd(AWSConsoleRootLogin):
    id = "AWS.CloudTrail.RootLoginProd"
    include_filters = [prod_account_filter]
    default_severity = Severity.HIGH

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
