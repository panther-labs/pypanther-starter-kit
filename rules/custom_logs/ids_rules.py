from pypanther import Rule, RuleTest, Severity
from pypanther.wrap import include

from helpers.custom_log_types import CustomLogType


# Base rule for a custom log type.
class HostIDSBaseRule(Rule):
    id = "HostIDS.BaseRule"
    enabled = True
    log_types = [CustomLogType.HOST_IDS]
    default_severity = Severity.HIGH
    threshold = 1
    dedup_period_minutes = 6 * 60  # 6 hours

    tests = [
        RuleTest(
            name="Confirmed Compromise",
            expected_result=True,
            expected_title="Confirmed [compromise] on host [host1]",
            expected_alert_context={"hostname": "host1", "time": "2021-01-01T00:00:00Z", "user": "groot"},
            log={
                "event_name": "confirmed_compromise",
                "host_name": "host1",
                "event_time": "2021-01-01T00:00:00Z",
                "user_agent": "Chrome",
            },
        )
    ]

    _compromise_type = "compromise"
    _title_message = "Confirmed [{compromise_type}] on host [{hostname}]"

    def host_user_lookup(self):
        return "groot"

    def rule(self, event):
        return event.get("event_name") == "confirmed_compromise"

    def title(self, event):
        return self._title_message.format(
            hostname=event.get("host_name"),
            compromise_type=self._compromise_type,
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
    id = "HostIDS.CommandAndControl"
    enabled = True
    threshold = 18
    _compromise_type = "command and control"

    tests = [
        RuleTest(
            name="Confirmed C2",
            expected_result=True,
            log={
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
    id = "HostIDS.Malware"
    enabled = True
    threshold = 2
    dedup_period_minutes = 60
    default_severity = Severity.CRITICAL
    _compromise_type = "malware"

    tests = [
        RuleTest(
            name="Confirmed Malware",
            expected_result=True,
            log={
                "event_name": "confirmed_compromise",
                "event_type": "malware",
                "host_name": "host1",
                "event_time": "2021-01-01T00:00:00Z",
                "user_agent": "Chrome",
            },
        )
    ]

    def rule(self, event):
        return super().rule(event) and event.get("event_type") == "malware"
