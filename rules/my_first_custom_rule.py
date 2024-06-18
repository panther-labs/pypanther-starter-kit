from pypanther import PantherLogType, PantherRule, PantherSeverity
from pypanther.base import PantherEvent


class MyFirstCustomRule(PantherRule):
    RuleID = "MyFirstCustomRule"
    LogTypes = [PantherLogType.AWS_CloudTrail]
    Severity = PantherSeverity.Low

    def rule(self, event: PantherEvent) -> bool:
        return False

    def title(self, event: PantherEvent) -> str:
        return "My first custom rule fired!"
