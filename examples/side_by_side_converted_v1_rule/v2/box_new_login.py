# Built-in box_new_login.py rule example

from pypanther import PantherLogType, PantherRule, PantherRuleTest, PantherSeverity

box_new_login_tests = [
    PantherRuleTest(
        Name="New test",
        ExpectedResult=True,
        Log={"event_type": "ADD_LOGIN_ACTIVITY_DEVICE"},
    )
]


class BoxNewLogin(PantherRule):
    RuleID = "Box.New.Login-prototype"
    DisplayName = "Box New Login"
    LogTypes = [PantherLogType.Box_Event]
    Tags = ["Box", "Initial Access:Valid Accounts"]
    Reports = {"MITRE ATT&CK": ["TA0001:T1078"]}
    Severity = PantherSeverity.Info
    Description = "A user logged in from a new device.\n"
    Reference = "https://support.box.com/hc/en-us/articles/360043691914-Controlling-Devices-Used-to-Access-Box"
    Runbook = "Investigate whether this is a valid user login.\n"
    SummaryAttributes = ["ip_address"]
    Tests = box_new_login_tests

    def rule(self, event):
        # ADD_LOGIN_ACTIVITY_DEVICE
        #  detect when a user logs in from a device not previously seen
        return event.get("event_type") == "ADD_LOGIN_ACTIVITY_DEVICE"

    def title(self, event):
        return f"User [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}] logged in from a new device."
