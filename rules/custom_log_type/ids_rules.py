from pypanther import PantherRule, PantherSeverity, PantherRuleTest
from pypanther.wrap import include

from helpers.custom_log_types import CustomLogType


# Base rule for a custom log type.
class HostIDSBaseRule(PantherRule):
    RuleID = "HostIDS.BaseRule"
    Enabled = True
    LogTypes = [CustomLogType.Host_IDS]
    Severity = PantherSeverity.High
    Threshold = 1
    DedupPeriodMinutes = 6 * 60  # 6 hours

    Tests = [
        PantherRuleTest(
            Name="Confirmed Comrpromise",
            ExpectedResult=True,
            Log={
                "event_name": "confirmed_compromise",
                "host_name": "host1",
                "event_time": "2021-01-01T00:00:00Z",
                "user_agent": "Chrome",
            },
        )
    ]

    _CompromiseType = "comprormise"
    _TitleMessage = "Confirmed [{compromise_type}] on host [{hostname}]"

    def host_user_lookup(self):
        return "groot"

    def rule(self, event):
        return event.get("event_name") == "confirmed_compromise"

    def title(self, event):
        return self._TitleMessage.format(
            hostname=event.get("host_name"),
            compromise_type=self._CompromiseType,
        )

    def alert_context(self, event):
        return {
            "hostname": event.get("host_name"),
            "time": event.get("event_time"),
            "user": self.host_user_lookup(),
        }


# Inherited rule #1
@include(lambda e: e.get("event_type") == "c2")
class HostIDSCommandAndControl(HostIDSBaseRule):
    RuleID = "HostIDS.CommandAndControl"
    Enabled = True
    Threshold = 18
    _CompromiseType = "command and control"

    Tests = [
        PantherRuleTest(
            Name="Confirmed C2",
            ExpectedResult=True,
            Log={
                "event_name": "confirmed_compromise",
                "event_type": "c2",
                "host_name": "host1",
                "event_time": "2021-01-01T00:00:00Z",
                "user_agent": "Chrome",
            },
        )
    ]


# Inherited rule #2
class HostIDSMalware(HostIDSBaseRule):
    RuleID = "HostIDS.Malware"
    Enabled = True
    Threshold = 2
    DedupPeriodMinutes = 60
    Severity = PantherSeverity.Critical
    _CompromiseType = "malware"

    def rule(self, event):
        return super().rule(event) and event.get("event_type") == "malware"

    Tests = [
        PantherRuleTest(
            Name="Confirmed Malware",
            ExpectedResult=True,
            Log={
                "event_name": "confirmed_compromise",
                "event_type": "malware",
                "host_name": "host1",
                "event_time": "2021-01-01T00:00:00Z",
                "user_agent": "Chrome",
            },
        )
    ]
