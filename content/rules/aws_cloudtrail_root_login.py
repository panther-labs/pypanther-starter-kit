from pypanther import LogType, Rule, RuleTest, Severity
from pypanther.rules.aws_cloudtrail import AWSConsoleRootLogin

from content.helpers.cloud import account_lookup_by_id, prod_account_ids


class CloudTrailRootLoginProd(AWSConsoleRootLogin):
    id = "AWS.CloudTrail.RootLogin.Prod"
    default_severity = Severity.MEDIUM
    default_description = "This rule is for auditing Console Root Logins and will escalate if MFA is not used."
    default_runbook = "Identify the user who assumed the root credentials either by pivoting on the IP address or checking the session context. Then, get a list of all events run by the root user for this session to determine if any actions were taken."

    def rule(self, event):
        # First check the parent rule's conditions
        if not super().rule(event):
            return False

        if event.get("recipientAccountId") not in prod_account_ids:
            return False

        return True

    def title(self, event):
        ip_address = event.get("sourceIPAddress")
        account = account_lookup_by_id(event.get("recipientAccountId"))
        return f"Root Login from [{ip_address}] in account [{account['accountName']}]"

    def severity(self, event):
        if event.deep_get("additionalEventData", "MFAUsed") == "No":
            return Severity.HIGH
        return self.default_severity

    tests = [
        RuleTest(
            name="Root Login from 136.90.223.255 in account [988776655444]",
            expected_title="Root Login from [136.90.223.255] in account [Blue]",
            expected_severity=Severity.HIGH,
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


# Optionally: Disable the parent rule
AWSConsoleRootLogin.override(enabled=False)
