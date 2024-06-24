from pypanther import PantherRuleTest, PantherSeverity
from pypanther.base import PantherEvent
from pypanther.rules.aws_cloudtrail_rules.aws_console_root_login import AWSConsoleRootLogin

req_dedup_fields = {
    "recipientAccountId": "",
    "eventName": "",
    "eventTime": "",
}

my_first_tuned_rule_tests = [
    PantherRuleTest(
        Name="not important",
        ExpectedResult=False,
        Log={"level": "not important"} | req_dedup_fields,
    ),
    PantherRuleTest(
        Name="important",
        ExpectedResult=True,
        Log={"level": "important"} | req_dedup_fields,
    ),
]


class MyFirstTunedRule(AWSConsoleRootLogin):
    RuleID = "MyFirstTunedRule"
    Severity = PantherSeverity.Low
    Tests = AWSConsoleRootLogin.Tests + my_first_tuned_rule_tests

    def rule(self, event: PantherEvent) -> bool:
        return self.is_important(event) or super().rule(event)

    def is_important(self, event: PantherEvent) -> bool:
        return event.get("level") == "important"
