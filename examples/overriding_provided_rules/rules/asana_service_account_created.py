from pypanther import PantherRuleTest, PantherSeverity
from pypanther.base import PantherEvent
from pypanther.rules.asana_rules.asana_service_account_created import (
    AsanaServiceAccountCreated,
)


class AsanaServiceAccountCreatedNoBigDeal(AsanaServiceAccountCreated):
    RuleID = "AsanaServiceAccountCreatedNoBigDeal"
    Severity = PantherSeverity.High
    # append a new test
    Tests = AsanaServiceAccountCreated.Tests + [
        PantherRuleTest(
            Name="test no big deal",
            ExpectedResult=False,
            Log={"event_type": "no big deal"},
        )
    ]

    def rule(self, event: PantherEvent) -> bool:
        if event.get("event_type") == "no big deal":
            return False

        return super().rule(event)
