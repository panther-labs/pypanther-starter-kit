from pypanther import PantherRuleTest
from pypanther.rules.asana_rules.asana_service_account_created import (
    AsanaServiceAccountCreated,
)
from pypanther.wrap import exclude, include


@exclude(lambda e: e.get("role") == "bully")
@include(lambda e: e.get("character", "honorable") == "honorable")
class AsanaServiceAccountCreatedNoBullies(AsanaServiceAccountCreated):
    RuleID = "AsanaServiceAccountCreatedNoBullies"
    Tests = AsanaServiceAccountCreated.Tests + [
        PantherRuleTest(
            Name="bully",
            ExpectedResult=False,
            Log={"role": "bully", "event_type": "service_account_created"},
        ),
        PantherRuleTest(
            Name="friend",
            ExpectedResult=True,
            Log={"role": "friend", "event_type": "service_account_created"},
        ),
        PantherRuleTest(
            Name="honorable",
            ExpectedResult=True,
            Log={"character": "honorable", "event_type": "service_account_created"},
        ),
        PantherRuleTest(
            Name="liar",
            ExpectedResult=False,
            Log={"character": "liar", "event_type": "service_account_created"},
        ),
    ]

    def title(self, event):
        return f"Asana event is a {event.get('character')} {event.get('role')}"
