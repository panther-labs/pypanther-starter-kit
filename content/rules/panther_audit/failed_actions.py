from pypanther import Rule, LogType, Severity, RuleTest


class PantherFailedActions(Rule):
    """Rule to detect failed actions in Panther audit logs."""
    id = "Custom.PantherAudit.FailedActions"
    display_name = "Panther Failed Actions"
    log_types = [LogType.PANTHER_AUDIT]
    threshold = 2
    enabled = True
    dedup_period_minutes = 90
    tags = ["Panther", "Audit", "Failed Actions", "Security"]
    default_severity = Severity.LOW
    default_reference = "https://docs.panther.com/system-configuration/panther-audit-logs"
    default_description = "Detects when actions in Panther fail, which could indicate misconfiguration, permissions issues, or potential security concerns."

    # Actions that are critical and should trigger higher severity alerts
    CRITICAL_ACTIONS = {
        "CREATE_USER",
        "DELETE_USER",
        "UPDATE_USER",
        "CREATE_API_TOKEN",
        "DELETE_API_TOKEN",
        "UPDATE_API_TOKEN",
        "CREATE_RSA_KEY",
        "UPDATE_SAML_SETTINGS",
        "CREATE_ALERT_DESTINATION",
        "UPDATE_ALERT_DESTINATION",
        "DELETE_ALERT_DESTINATION"
    }

    def rule(self, event):
        # Check if the action failed
        action_result = event.get("actionResult", "")
        return action_result in ["FAILED", "PARTIALLY_FAILED"]

    def title(self, event):
        action = event.get("actionName", "<UNKNOWN_ACTION>")
        actor_info = event.get("actor", {})
        actor_name = actor_info.get("name", "<UNKNOWN_ACTOR>")
        actor_type = actor_info.get("type", "USER")
        
        return f"Failed Panther Action: {action} by {actor_type} {actor_name}"

    def severity(self, event):
        action = event.get("actionName")
        
        # Critical actions that failed should be high severity
        if action in self.CRITICAL_ACTIONS:
            return Severity.HIGH
            
        # If there are multiple errors, increase severity
        errors = event.get("errors", [])
        if len(errors) > 1:
            return Severity.HIGH
            
        return self.default_severity

    def runbook(self, event):
        action = event.get("actionName", "")
        errors = event.get("errors", [])
        error_messages = "\n".join([f"- {error.get('message', '')}" for error in errors])
        
        return f"""
## Investigation Steps

1. Review the failed action: {action}
2. Check the error messages:
{error_messages}

3. Verify if this was an expected failure or potential security issue
4. Check the source IP and user agent for suspicious activity
5. Review the actor's recent activity for patterns of failures
6. If the action is critical (user/token management, SAML settings, etc.), escalate to security team

## Remediation Steps

1. If permission-related:
   - Verify the actor has appropriate permissions
   - Review and update IAM policies if needed

2. If configuration-related:
   - Check Panther configuration settings
   - Verify input parameters are correct

3. If suspicious:
   - Lock affected accounts/tokens
   - Review audit logs for related activity
   - Investigate potential security implications
"""

    tests = [
        RuleTest(
            name="Failed User Creation",
            expected_result=True,
            log={
                "actionName": "CREATE_USER",
                "actionDescription": "Create new user account",
                "actionResult": "FAILED",
                "actor": {
                    "id": "user123",
                    "type": "USER",
                    "name": "admin.user",
                    "attributes": {"email": "admin@example.com"}
                },
                "errors": [{
                    "message": "User already exists"
                }],
                "sourceIP": "192.0.2.1",
                "userAgent": "Mozilla/5.0",
                "timestamp": "2024-02-07T00:00:00Z",
                "pantherVersion": "1.39.0"
            }
        ),
        RuleTest(
            name="Failed API Token Creation with Multiple Errors",
            expected_result=True,
            log={
                "actionName": "CREATE_API_TOKEN",
                "actionResult": "FAILED",
                "actor": {
                    "id": "user456",
                    "type": "USER",
                    "name": "service.account"
                },
                "errors": [
                    {"message": "Invalid permissions specified"},
                    {"message": "Token name already in use"}
                ],
                "sourceIP": "192.0.2.2",
                "timestamp": "2024-02-07T00:00:00Z",
                "pantherVersion": "1.39.0"
            }
        ),
        RuleTest(
            name="Successful Action",
            expected_result=False,
            log={
                "actionName": "LIST_USERS",
                "actionResult": "SUCCEEDED",
                "actor": {
                    "id": "user789",
                    "type": "USER",
                    "name": "readonly.user"
                },
                "sourceIP": "192.0.2.3",
                "timestamp": "2024-02-07T00:00:00Z",
                "pantherVersion": "1.39.0"
            }
        ),
        RuleTest(
            name="Partially Failed Action",
            expected_result=True,
            log={
                "actionName": "BULK_UPLOAD_DETECTIONS",
                "actionResult": "PARTIALLY_FAILED",
                "actor": {
                    "id": "user101",
                    "type": "USER",
                    "name": "security.analyst"
                },
                "errors": [{
                    "message": "Some detections failed to upload"
                }],
                "sourceIP": "192.0.2.4",
                "timestamp": "2024-02-07T00:00:00Z",
                "pantherVersion": "1.39.0"
            }
        )
    ] 