from pypanther import Rule, Severity, LogType


# Custom rule for a Panther-supported log type
class MyCloudTrailRule(Rule):
    id = "MyCloudTrailRule"
    tests = True
    log_types = [LogType.AWS_CLOUDTRAIL]
    default_severity = Severity.MEDIUM
    threshold = 50
    dedup_period_minutes = 1

    def rule(self, event) -> bool:
        return (
                event.get("eventType") == "AssumeRole" and
                400 <= int(event.get("errorCode", 0)) <= 413
        )
