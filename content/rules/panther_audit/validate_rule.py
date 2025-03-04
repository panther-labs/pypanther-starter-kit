from pypanther import LogType, Rule, Severity


class PantherAuditUploadArtifacts(Rule):
    enabled = True
    id = "Custom.PantherAudit.UploadArtifacts"
    log_types = [LogType.PANTHER_AUDIT]
    tags = ["Compliance"]
    default_severity = Severity.INFO
    create_alert = False
    # The name of the API token
    allowed_users: list[str] = ["new"]

    def rule(self, event):
        return (
            event.get("actionName") == "BULK_UPLOAD_DETECTIONS"
            and event.deep_get("actor", "name") in self.allowed_users
        )

    @classmethod
    def validate_config(cls):
        assert len(cls.allowed_users) > 0, "allowed_users must be set"
