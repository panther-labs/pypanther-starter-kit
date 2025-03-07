from pypanther import LogType, Rule, RuleTest, Severity


class PantherRuleModificationOutsideCICD(Rule):
    id = "Custom.PantherAudit.RuleModificationOutsideCICD"
    display_name = "Panther Rule Modified Outside CICD"
    log_types = [LogType.PANTHER_AUDIT]
    enabled = True
    dedup_period_minutes = 60
    tags = ["Panther", "CICD", "Change Management", "Security"]
    default_severity = Severity.HIGH
    default_reference = "https://docs.panther.com/guides/ci-cd"
    default_description = (
        "Detects when users modify Panther rules outside of the expected CICD process. "
        "All rule changes should be made through version control and deployed via CICD."
    )

    # Actions that indicate rule modifications
    RULE_MODIFICATION_ACTIONS = {
        # Direct rule changes
        "CREATE_RULE",
        "UPDATE_RULE_AND_FILTER",
        "BULK_UPLOAD_DETECTIONS",
        # State changes that could enable/disable rules
        "UPDATE_DETECTION_STATE",
        # Pack-level changes that could affect rules
        "UPDATE_DETECTION_PACK_STATE",
    }

    # The authorized CICD service account
    AUTHORIZED_CICD_USERS = ["api-token-cicd"]

    def rule(self, event):
        # Check if this is a rule modification action
        if event.get("actionName") not in self.RULE_MODIFICATION_ACTIONS:
            return False

        # Check if the action was performed by someone other than our CICD user
        actor_name = event.deep_get("actor", "name")
        if actor_name in self.AUTHORIZED_CICD_USERS:
            return False

        # Alert on any rule modifications by other users
        return True

    def title(self, event):
        action = event.get("actionName")
        actor = event.deep_get("actor", "name")
        return f"Panther Rule Modified Outside CICD Process - {action} by {actor}"

    def alert_context(self, event):
        return {
            # Who made the change
            "actor_name": event.deep_get("actor", "name"),
            "actor_email": event.deep_get("actor", "attributes", "email"),
            "actor_role": event.deep_get("actor", "attributes", "roleName"),
            # What was changed
            "action": event.get("actionName"),
            "rule_id": event.deep_get("actionDetails", "addRule.id"),
            "rule_display_name": event.deep_get("actionParams", "dynamic", "input", "displayName"),
            "log_types": event.deep_get("actionParams", "dynamic", "input", "logTypes"),
            "severity": event.deep_get("actionParams", "dynamic", "input", "severity"),
            # When and where
            "timestamp": event.get("timestamp"),
            "source_ip": event.get("sourceIP"),
            "user_agent": event.get("userAgent"),
            # Status
            "status": event.get("actionResult"),
        }

    def severity(self, event):
        action = event.get("actionName")

        # Higher severity for direct rule modifications
        if action in {"CREATE_RULE", "UPDATE_RULE_AND_FILTER", "BULK_UPLOAD_DETECTIONS"}:
            return Severity.HIGH

        # Medium severity for state changes
        return Severity.MEDIUM

    @classmethod
    def validate_config(cls):
        assert len(cls.AUTHORIZED_CICD_USERS) > 0, "AUTHORIZED_CICD_USERS must be set"

    tests = [
        RuleTest(
            name="Unauthorized Rule Creation",
            expected_result=True,
            log={
                "actionName": "CREATE_RULE",
                "actor": {"name": "alice", "email": "alice@company.com"},
                "sourceIP": "192.0.2.1",
                "userAgent": "Mozilla/5.0",
                "timestamp": "2024-03-20T00:00:00Z",
                "actionResult": "SUCCEEDED",
                "requestParameters": {"detectionIds": ["Custom.Rule.Test"], "detectionTypes": ["RULE"]},
            },
        ),
        RuleTest(
            name="Authorized CICD Update",
            expected_result=False,
            log={
                "actionName": "BULK_UPLOAD_DETECTIONS",
                "actor": {"name": "api-token-cicd", "email": "cicd@company.com"},
                "sourceIP": "192.0.2.2",
                "timestamp": "2024-03-20T00:00:00Z",
                "actionResult": "SUCCEEDED",
                "requestParameters": {
                    "detectionIds": ["Custom.Rule.Test1", "Custom.Rule.Test2"],
                    "detectionTypes": ["RULE", "RULE"],
                },
            },
        ),
        RuleTest(
            name="Unauthorized Rule State Change",
            expected_result=True,
            log={
                "actionName": "UPDATE_DETECTION_STATE",
                "actor": {"name": "bob", "email": "bob@company.com"},
                "sourceIP": "192.0.2.3",
                "timestamp": "2024-03-20T00:00:00Z",
                "actionResult": "SUCCEEDED",
                "requestParameters": {"detectionIds": ["Custom.Rule.Test"], "enabled": True},
            },
        ),
        RuleTest(
            name="Non-Rule Action",
            expected_result=False,
            log={
                "actionName": "LIST_DETECTIONS",
                "actor": {"name": "alice", "email": "alice@company.com"},
                "sourceIP": "192.0.2.4",
                "timestamp": "2024-03-20T00:00:00Z",
                "actionResult": "SUCCEEDED",
            },
        ),
    ]