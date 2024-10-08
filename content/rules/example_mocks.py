from pypanther import RuleTest, Rule, RuleMock, LogType, Severity


# This is an example of how to use mocks in your tests.
# The mocks are used to replace the actual object with a mock object.
# The mock object can be a new object, a return value, or a side effect.
# You can mock objects that are defined in the rule class or outside of the rule class.
# http://www.ines-panker.com/2020/06/01/python-mock.html

OUTSIDE = "outside"
def outside():
    return OUTSIDE

class MockTestRule(Rule):
    id = "mock_test_rule"
    display_name = "Mock Test Rule"
    default_description = "This rule provides an example of how to mock objects within a rule in rule tests."
    log_types = [LogType.AZURE_AUDIT]
    default_severity = Severity.INFO
    create_alert = False

    VARIABLE = []

    def rule(self, event):
        return self.VARIABLE != []
    
    tests = [
        RuleTest(
            name="Mock new Test",
            expected_result=True,
            mocks=[
                RuleMock(
                    # Mock the object VARIABLE with a new object ["test"]
                    object_name="VARIABLE",
                    new=["test"]
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
        RuleTest(
            name="Mock side_effect Test",
            expected_result=True,
            mocks=[
                RuleMock(
                    # Mock the method rule() with a side effect that checks if the action is "Blocked"
                    object_name="rule",
                    side_effect=lambda e: e.get("action") == "Blocked"
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
        RuleTest(
            name="Mock return_value Test",
            expected_result=True,
            mocks=[
                RuleMock(
                    # Mock the method rule() with a return value of True
                    object_name="rule",
                    return_value=True
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
    ]


    
class OutsideMockTest(Rule):
    id = "outside_mock_test"
    display_name = "Outside Mock Test"
    default_description = "This rule provides an example of how to mock objects outside of the rule class in rule tests."
    log_types = [LogType.AZURE_AUDIT]
    default_severity = Severity.INFO
    create_alert = False

    def rule(self, event):
        return outside() == "outside"
    
    tests = [
        RuleTest(
            name="Mock outside new",
            expected_result=False,
            mocks=[
                RuleMock(
                    # Mock the object OUTSIDE with a new value "inside"
                    object_name="OUTSIDE",
                    new="inside"
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
        RuleTest(
            name="Mock outside return_value",
            expected_result=False,
            mocks=[
                RuleMock(
                    # Mock the function outside() with a return value "inside"
                    object_name="outside",
                    return_value="inside"
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
        RuleTest(
            name="Mock outside side_effect",
            expected_result=False,
            mocks=[
                RuleMock(
                    # Mock the function outside() with a side effect that returns "inside"
                    object_name="outside",
                    side_effect=lambda: "inside"
                )
            ],
            log={
                "action": "Blocked",
                "internalIp": ""
            }
        ),
    ]
