from pypanther import Rule, LogType, Severity, RuleTest


class PantherAdminActions(Rule):
    id = "Custom.PantherAudit.AdminActions"
    display_name = "Panther Administrative Actions"
    log_types = [LogType.PANTHER_AUDIT]
    enabled = True
    dedup_period_minutes = 60
    tags = ["Compliance"]
    default_severity = Severity.HIGH
    default_reference = "https://docs.panther.com/system-configuration/panther-audit-logs"
    default_description = "Detects when administrative actions are performed in Panther that could impact system security or access controls."

    # Administrative actions that we want to monitor
    ADMIN_ACTIONS = {
        # User Management
        "CREATE_USER",
        "DELETE_USER",
        "UPDATE_USER",
        "CREATE_USER_ROLE",
        "DELETE_USER_ROLE",
        "UPDATE_USER_ROLE",
        "RESET_USER_PASSWORD",
        
        # Authentication & Access Control
        "CREATE_API_TOKEN",
        "DELETE_API_TOKEN",
        "UPDATE_API_TOKEN",
        "CREATE_RSA_KEY",
        "UPDATE_SAML_SETTINGS",
        "GET_SAML_SETTINGS",
        
        # Alert Configuration
        "CREATE_ALERT_DESTINATION",
        "UPDATE_ALERT_DESTINATION",
        "DELETE_ALERT_DESTINATION",
        
        # System Configuration
        "UPDATE_GENERAL_SETTINGS",
        "UPDATE_UNIVERSAL_SETTINGS",
        "GET_SUPPORT_LOGIN_CONFIG",
        "UPDATE_SUPPORT_LOGIN_SETTINGS",
        
        # Cloud Account Management
        "CREATE_CLOUD_ACCOUNT",
        "DELETE_CLOUD_ACCOUNT",
        "UPDATE_CLOUD_ACCOUNT",
        
        # Detection Management
        "CREATE_DETECTION_PACK_SOURCE",
        "DELETE_DETECTION_PACK_SOURCE",
        "UPDATE_DETECTION_PACK_SOURCE",
        "UPDATE_DETECTION_PACK_STATE",
        
        # Data Source Management
        "CREATE_LOG_SOURCE",
        "DELETE_LOG_SOURCE",
        "UPDATE_LOG_SOURCE"
    }

    def rule(self, event):
        # Check if this is an administrative action
        action = event.get("actionName")
        if action not in self.ADMIN_ACTIONS:
            return False
            
        # Always alert on successful admin actions
        if event.get("actionResult") == "SUCCEEDED":
            return True

        # For failed actions, only alert if they have errors
        # This helps reduce noise from simple validation failures
        if event.get("actionResult") in ["FAILED", "PARTIALLY_FAILED"]:
            return bool(event.get("errors"))
            
        return False

    def title(self, event):
        actor_name = event.deep_get("actor", "name")
        return f"Administrative Actions in Panther taken by [{actor_name}]"

    def alert_context(self, event):
        actor_info = event.get("actor", {})
        
        context = {
            "action": {
                "name": event.get("actionName"),
                "description": event.get("actionDescription"),
                "result": event.get("actionResult"),
                "parameters": event.get("actionParams"),
                "details": event.get("actionDetails")
            },
            "actor": {
                "id": actor_info.get("id"),
                "type": actor_info.get("type"),
                "name": actor_info.get("name"),
                "attributes": actor_info.get("attributes")
            },
            "errors": event.get("errors", []),
            "source_ip": event.get("sourceIP"),
            "x_forwarded_for": event.get("XForwardedFor", []),
            "user_agent": event.get("userAgent"),
            "timestamp": event.get("timestamp"),
            "panther_version": event.get("pantherVersion")
        }        
        return context

    tests = [
        RuleTest(
            name="Successful User Creation",
            expected_result=True,
            log={
                "actionName": "CREATE_USER",
                "actionDescription": "Create new user account",
                "actionResult": "SUCCEEDED",
                "actor": {
                    "id": "user123",
                    "type": "USER",
                    "name": "admin.user",
                    "attributes": {"email": "admin@example.com"}
                },
                "sourceIP": "192.0.2.1",
                "userAgent": "Mozilla/5.0",
                "timestamp": "2024-02-07T00:00:00Z",
                "pantherVersion": "1.39.0"
            }
        ),
        RuleTest(
            name="Failed SAML Settings Update",
            expected_result=True,
            log={
                "actionName": "UPDATE_SAML_SETTINGS",
                "actionResult": "FAILED",
                "actor": {
                    "id": "user456",
                    "type": "USER",
                    "name": "security.admin"
                },
                "errors": [{
                    "message": "Invalid SAML certificate format"
                }],
                "sourceIP": "192.0.2.2",
                "timestamp": "2024-02-07T00:00:00Z",
                "pantherVersion": "1.39.0"
            }
        ),
        RuleTest(
            name="Non-administrative Action",
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
            name="Failed Admin Action Without Errors",
            expected_result=False,
            log={
                "actionName": "CREATE_API_TOKEN",
                "actionResult": "FAILED",
                "actor": {
                    "id": "user101",
                    "type": "USER",
                    "name": "service.account"
                },
                "sourceIP": "192.0.2.4",
                "timestamp": "2024-02-07T00:00:00Z",
                "pantherVersion": "1.39.0"
            }
        )
    ] 