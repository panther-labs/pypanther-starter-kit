from panther_core import PantherEvent
from pypanther import Rule, Severity, LogType
from pypanther.rules.asana import AsanaServiceAccountCreated


class MyRule(AsanaServiceAccountCreated):
    id = "MyRule"
    default_severity = Severity.MEDIUM

    ips = ["1.1.1.1"]

    def rule(self, event: PantherEvent) -> bool:
        return  event.get("context", {}).get("client_ip_address") in self.ips