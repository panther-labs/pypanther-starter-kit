from pypanther import Rule, LogType, Severity, RuleTest


class GoogleWorkspaceLoginTracking(Rule):
    id = "Custom.GoogleWorkspace.JackLoginTracking"
    display_name = "Google Workspace Login Activity - Jack"
    log_types = [LogType.GSUITE_ACTIVITY_EVENT]
    enabled = True
    dedup_period_minutes = 60
    tags = ["Google Workspace", "Login", "Security"]
    default_severity = Severity.LOW
    default_reference = "https://developers.google.com/admin-sdk/audit/reference/rest/v1/activities"
    default_description = "Tracks login activity for a specific user in Google Workspace."

    def rule(self, event):
        # Check if this is a login event
        if event.deep_get('id', 'applicationName') != 'login':
            return False
        
        # Check if this is a reauth event (we want to ignore these)
        if event.deep_get('parameters', 'login_type') == 'reauth':
            return False
        
        # Check if this is for the specific email we're tracking
        return event.deep_get('actor', 'email') == 'jack@naglieri.co'

    def title(self, event):
        email = event.deep_get('actor', 'email')
        return f"Google Workspace Login Activity - [{email}]"

    def alert_context(self, event):
        return {
            'ip_address': event.deep_get('ipAddress'),
            'login_type': event.deep_get('name'),
            'user_email': event.deep_get('actor', 'email'),
            'browser': event.deep_get('parameters', 'browser'),
            'device_type': event.deep_get('parameters', 'device_type'),
        }

    tests = [
        RuleTest(
            name="Successful Login",
            expected_result=True,
            log={
                'id': {'applicationName': 'login'},
                'actor': {'email': 'jack@naglieri.co'},
                'parameters': {
                    'login_type': 'normal',
                    'browser': 'Chrome',
                    'device_type': 'desktop'
                },
                'ipAddress': '192.0.2.1',
                'name': 'login_success'
            }
        ),
        RuleTest(
            name="Reauth Event",
            expected_result=False,
            log={
                'id': {'applicationName': 'login'},
                'actor': {'email': 'jack@naglieri.co'},
                'parameters': {
                    'login_type': 'reauth',
                    'browser': 'Chrome',
                    'device_type': 'desktop'
                },
                'ipAddress': '192.0.2.1',
                'name': 'login_reauth'
            }
        ),
        RuleTest(
            name="Non-login Event",
            expected_result=False,
            log={
                'id': {'applicationName': 'drive'},
                'actor': {'email': 'jack@naglieri.co'},
                'parameters': {
                    'browser': 'Chrome',
                    'device_type': 'desktop'
                },
                'ipAddress': '192.0.2.1',
                'name': 'file_access'
            }
        ),
        RuleTest(
            name="Different User",
            expected_result=False,
            log={
                'id': {'applicationName': 'login'},
                'actor': {'email': 'other@example.com'},
                'parameters': {
                    'login_type': 'normal',
                    'browser': 'Chrome',
                    'device_type': 'desktop'
                },
                'ipAddress': '192.0.2.1',
                'name': 'login_success'
            }
        )
    ]
