from pypanther import PantherLogType, PantherRule, PantherSeverity
from pypanther.base import PantherEvent


class AwsRule1(PantherRule):
    RuleID = "AwsRule1"
    LogTypes = [PantherLogType.AWS_ALB]
    Severity = PantherSeverity.High

    def rule(self, event: PantherEvent) -> bool:
        # insert real logic here
        return False


class AwsRule2(PantherRule):
    RuleID = "AwsRule2"
    LogTypes = [PantherLogType.AWS_CloudWatchEvents]
    Severity = PantherSeverity.High

    def rule(self, event: PantherEvent) -> bool:
        # insert real logic here
        return False


class AwsRule3(PantherRule):
    RuleID = "AwsRule3"
    LogTypes = [PantherLogType.AWS_CloudTrail]
    Severity = PantherSeverity.High

    def rule(self, event: PantherEvent) -> bool:
        # insert real logic here
        return False
