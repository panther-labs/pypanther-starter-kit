# This is an example of a rule with explicit types.  The base Rule class is typed,
# so if you inherit from it, explicit typing is optional.  However, if you want to
# be explicit about the types, you can do so like this:

from typing import Dict, List

from panther_core.enriched_event import PantherEvent
from pydantic import NonNegativeInt, PositiveInt
from pypanther import LogType, Rule, RuleTest, Severity
from pypanther.base import SeverityType
from pypanther.helpers.base import aws_guardduty_context
from pypanther.severity import SEVERITY_DEFAULT
from time import strptime


class MyTypedRule(Rule):
    log_types: List[LogType | str] = [LogType.AWS_GUARDDUTY]
    id: str = "AWS.GuardDuty.HighVolFindings"
    create_alert: bool = True
    dedup_period_minutes: NonNegativeInt = 45
    display_name: str = "High volume of GuardDuty findings"
    enabled: bool = True
    threshold: PositiveInt = 100
    tags: List[str] = ["GuardDuty", "Security"]
    reports: Dict[str, List[str]] = {"MITRE ATT&CK": ["TA0010:T1499"]}

    default_severity: Severity | str = Severity.HIGH
    default_destinations: List[str] = ["slack:my-channel"]
    default_description: str = "This rule tracks high volumes of GuardDuty findings"

    def rule(self, event: PantherEvent) -> bool:
        if event.deep_get("service", "additionalInfo", "sample"):
            # in case of sample data
            # https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html
            return False
        return 7.0 <= float(event.get("severity", 0)) <= 8.9

    def title(self, event: PantherEvent) -> str:
        return event.get("title", "GuardDuty finding")

    def severity(self, event: PantherEvent) -> SeverityType:
        # Parse timestamp: "createdAt": "2020-02-14T18:12:22.316Z"
        timestamp = strptime(event.get("createdAt", "1970-01-01T00:00:00Z"), "%Y-%m-%dT%H:%M:%S.%fZ")
        # Increase severity if it's the weekend
        if timestamp.tm_wday in (5, 6):
            return Severity.CRITICAL
        return SEVERITY_DEFAULT

    def alert_context(self, event: PantherEvent) -> dict:
        return aws_guardduty_context(event)

    tests: List[RuleTest] = [
        RuleTest(
            name="High Sev Finding",
            expected_result=True,
            log={
                "schemaVersion": "2.0",
                "accountId": "123456789012",
                "region": "us-east-1",
                "partition": "aws",
                "arn": "arn:aws:guardduty:us-west-2:123456789012:detector/111111bbbbbbbbbb5555555551111111/finding/90b82273685661b9318f078d0851fe9a",
                "type": "PrivilegeEscalation:IAMUser/AdministrativePermissions",
                "service": {
                    "serviceName": "guardduty",
                    "detectorId": "111111bbbbbbbbbb5555555551111111",
                    "action": {
                        "actionType": "AWS_API_CALL",
                        "awsApiCallAction": {
                            "api": "PutRolePolicy",
                            "serviceName": "iam.amazonaws.com",
                            "callerType": "Domain",
                            "domainDetails": {"domain": "cloudformation.amazonaws.com"},
                            "affectedResources": {"AWS::IAM::Role": "arn:aws:iam::123456789012:role/IAMRole"},
                        },
                    },
                    "resourceRole": "TARGET",
                    "additionalInfo": {},
                    "evidence": None,
                    "eventFirstSeen": "2020-02-14T17:59:17Z",
                    "eventLastSeen": "2020-02-14T17:59:17Z",
                    "archived": False,
                    "count": 1,
                },
                "severity": 8,
                "id": "eeb88ab56556eb7771b266670dddee5a",
                "createdAt": "2020-02-14T18:12:22.316Z",
                "updatedAt": "2020-02-14T18:12:22.316Z",
                "title": "Principal AssumedRole:IAMRole attempted to add a policy to themselves that is highly permissive.",
                "description": "Principal AssumedRole:IAMRole attempted to add a highly permissive policy to themselves.",
            },
        ),
        RuleTest(
            name="High Sev Finding As Sample Data",
            expected_result=False,
            log={
                "schemaVersion": "2.0",
                "accountId": "123456789012",
                "region": "us-east-1",
                "partition": "aws",
                "arn": "arn:aws:guardduty:us-west-2:123456789012:detector/111111bbbbbbbbbb5555555551111111/finding/90b82273685661b9318f078d0851fe9a",
                "type": "PrivilegeEscalation:IAMUser/AdministrativePermissions",
                "service": {
                    "serviceName": "guardduty",
                    "detectorId": "111111bbbbbbbbbb5555555551111111",
                    "action": {
                        "actionType": "AWS_API_CALL",
                        "awsApiCallAction": {
                            "api": "PutRolePolicy",
                            "serviceName": "iam.amazonaws.com",
                            "callerType": "Domain",
                            "domainDetails": {"domain": "cloudformation.amazonaws.com"},
                            "affectedResources": {"AWS::IAM::Role": "arn:aws:iam::123456789012:role/IAMRole"},
                        },
                    },
                    "resourceRole": "TARGET",
                    "additionalInfo": {"sample": True},
                    "evidence": None,
                    "eventFirstSeen": "2020-02-14T17:59:17Z",
                    "eventLastSeen": "2020-02-14T17:59:17Z",
                    "archived": False,
                    "count": 1,
                },
                "severity": 8,
                "id": "eeb88ab56556eb7771b266670dddee5a",
                "createdAt": "2020-02-14T18:12:22.316Z",
                "updatedAt": "2020-02-14T18:12:22.316Z",
                "title": "Principal AssumedRole:IAMRole attempted to add a policy to themselves that is highly permissive.",
                "description": "Principal AssumedRole:IAMRole attempted to add a highly permissive policy to themselves.",
            },
        ),
    ]
