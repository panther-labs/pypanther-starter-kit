from pypanther import LogType, Rule, Severity


class ValidateMyRule(Rule):
    id = "Custom.Validate.MyRule"
    severity = Severity.INFO
    log_types = [LogType.PANTHER_AUDIT]
    default_severity = Severity.HIGH

    allowed_domains: list[str] = []

    def rule(self, event):
        return event.get("domain") in self.allowed_domains

    @classmethod
    def validate_config(cls):
        assert len(cls.allowed_domains) > 0, "The allowed_domains field on your must be populated"
