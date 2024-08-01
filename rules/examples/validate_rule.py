from pypanther import LogType, Rule, Severity


class PantherAuditUploadArtifacts(Rule):
    enabled = False
    id = "Custom.PantherAudit.UploadArtifacts"
    log_types = [LogType.PANTHER_AUDIT]
    default_severity = Severity.HIGH

    allowed_users: list[str] = ["PAT Upload"]

    def rule(self, event):
        return (
            event.get("actionName") == "UPLOAD_DETECTION_ENTITIES_ASYNC"
            and event.deep_get("actor", "name") in self.allowed_users
        )

    @classmethod
    def validate_config(cls):
        assert len(cls.allowed_users) > 0, "allowed_users must be set"
