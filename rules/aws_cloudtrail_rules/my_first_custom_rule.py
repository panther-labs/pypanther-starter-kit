from pypanther import PantherLogType, PantherRule, PantherRuleTest, PantherSeverity
from pypanther.base import PantherEvent

tests = [
    PantherRuleTest(
        Name="should be false",
        ExpectedResult=False,
        Log={"field": "val"},
    )
]


class MyFirstCustomRule(PantherRule):
    RuleID = "MyFirstCustomRule"
    LogTypes = [PantherLogType.AWS_CloudTrail]
    Severity = PantherSeverity.Low
    Tests = tests

    def rule(self, event: PantherEvent) -> bool:
        return False

    def title(self, event: PantherEvent) -> str:
        return "My first custom rule fired!"
