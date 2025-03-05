from pypanther import LogType, Rule, RuleTest, Severity


class GoogleWorkspaceNonPasskeyLogin(Rule):
    id = "Custom.GoogleWorkspace.NonPasskeyLogin"
    display_name = "Google Workspace Login Without Passkey"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    enabled = True
    dedup_period_minutes = 60
    tags = ["Google Workspace", "Login", "Security", "Passkey"]
    default_severity = Severity.LOW
    default_reference = "https://developers.google.com/admin-sdk/audit/reference/rest/v1/activities"
    default_description = "Detects when users log in to Google Workspace without using a passkey."

    def rule(self, event):
        # Check if this is a login event
        if event.deep_get("id", "applicationName") != "login":
            return False

        # Check if this is a reauth event (we want to ignore these)
        if event.deep_get("parameters", "login_type") == "reauth":
            return False

        # Check if the login challenge method includes passkey
        login_challenge_methods = event.deep_get("parameters", "login_challenge_method") or []
        return "passkey" not in login_challenge_methods

    def title(self, event):
        email = event.deep_get("actor", "email")
        login_challenge_methods = event.deep_get("parameters", "login_challenge_method") or []
        methods = ", ".join(login_challenge_methods) if login_challenge_methods else "unknown"
        return f"Non-Passkey Login Detected - [{email}] using {methods}"

    def alert_context(self, event):
        return {
            "ip_address": event.deep_get("ipAddress"),
            "login_type": event.deep_get("name"),
            "user_email": event.deep_get("actor", "email"),
            "login_challenge_methods": event.deep_get("parameters", "login_challenge_method", []),
            "is_second_factor": event.deep_get("parameters", "is_second_factor", False),
            "login_challenge_status": event.deep_get("parameters", "login_challenge_status"),
        }

    tests = [
        RuleTest(
            name="Password Login",
            expected_result=True,
            expected_title="Non-Passkey Login Detected - [user@example.com] using unknown",
            log={
                "id": {"applicationName": "login"},
                "actor": {"email": "user@example.com"},
                "parameters": {
                    "login_type": "google_password"
                },
                "ipAddress": "192.0.2.1",
                "name": "login_verification",
            },
        ),
        RuleTest(
            name="Passkey Login",
            expected_result=False,
            expected_title="Non-Passkey Login Detected - [user@example.com] using passkey",
            log={
                "id": {"applicationName": "login"},
                "actor": {"email": "user@example.com"},
                "parameters": {
                    "login_type": "google_password",
                    "login_challenge_method": ["passkey"],
                    "is_second_factor": True,
                    "login_challenge_status": "passed"
                },
                "ipAddress": "192.0.2.1",
                "name": "login_verification",
            },
        ),
        RuleTest(
            name="Reauth Event",
            expected_result=False,
            expected_title="Non-Passkey Login Detected - [user@example.com] using password",
            log={
                "id": {"applicationName": "login"},
                "actor": {"email": "user@example.com"},
                "parameters": {
                    "login_type": "reauth",
                    "login_challenge_method": ["password"],
                    "is_second_factor": False,
                    "login_challenge_status": "passed"
                },
                "ipAddress": "192.0.2.1",
                "name": "login_reauth",
            },
        ),
        RuleTest(
            name="Non-login Event",
            expected_result=False,
            expected_title="Non-Passkey Login Detected - [user@example.com] using unknown",
            log={
                "id": {"applicationName": "drive"},
                "actor": {"email": "user@example.com"},
                "parameters": {
                    "browser": "Chrome",
                    "device_type": "desktop"
                },
                "ipAddress": "192.0.2.1",
                "name": "file_access",
            },
        ),
    ] 