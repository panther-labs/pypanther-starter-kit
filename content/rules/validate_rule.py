from pypanther import LogType, Rule, RuleTest, Severity


class PantherAuditUploadArtifacts(Rule):
    enabled = True
    id = "Custom.PantherAudit.UploadArtifacts"
    log_types = [LogType.PANTHER_AUDIT]
    default_severity = Severity.HIGH

    allowed_users: list[str] = ["jack@panther.com"]

    base_alert_context = {"confidence": 5, "impact": 10}

    tests = [
        RuleTest(
            name="Confirmed Compromise",
            expected_result=True,
            log={"actionName": "UPLOAD_DETECTION_ENTITIES_ASYNC", "actor": {"name": "alice@panther.com"}},
            expected_alert_context={
                "confidence": 5,
                "impact": 10,
                "actionName": "UPLOAD_DETECTION_ENTITIES_ASYNC",
                "actor": {"name": "alice@panther.com"},
            },
        ),
    ]

    def rule(self, event):
        return (
            event.get("actionName") == "UPLOAD_DETECTION_ENTITIES_ASYNC"
            and event.deep_get("actor", "name") not in self.allowed_users
        )

    def alert_context(self, event):
        return {
            **self.base_alert_context,
            "actionName": event.get("actionName"),
            "actor": event.get("actor"),
        }

    @classmethod
    def validate_config(cls):
        assert len(cls.allowed_users) > 0, "allowed_users must be set"
