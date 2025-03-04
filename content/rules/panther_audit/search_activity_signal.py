from pypanther import Rule, LogType, RuleTest, Severity


class PantherAuditSearchActivity(Rule):
    id = "Custom.PantherAudit.SearchActivity"
    display_name = "Panther Audit Log Search Activity"
    log_types = [LogType.PANTHER_AUDIT]
    tags = ["Compliance"]
    default_reference = "https://docs.panther.com/system-configuration/panther-audit-logs"
    default_description = "Detects when users perform search or query operations in Panther."
    default_severity = Severity.INFO
    create_alert = False
    enabled = True

    # Search and query related operations in Panther
    SEARCH_OPERATIONS = {
        "EXECUTE_DATA_LAKE_QUERY",
        "EXECUTE_INDICATOR_SEARCH_QUERY",
        "EXECUTE_SIMPLE_SEARCH_QUERY",
        "EXECUTE_UBER_SEARCH",
        "EXECUTE_UBER_SEARCH_PROPERTY_SUMMARY",
        "GENERATE_DATA_LAKE_SQL_QUERY_SNIPPET",
        "GENERATE_SIMPLE_SEARCH_QUERY",
        "GENERATE_UBER_SEARCH_QUERY",
        "GET_DATA_LAKE_QUERY",
        "GET_DATA_LAKE_QUERY_SUMMARY",
        "GET_UBER_SEARCH",
        "GET_UBER_SEARCH_VISUALIZATION",
        "LIST_DATA_LAKE_QUERIES",
        "SUMMARIZE_DATA_LAKE_QUERY",
        "UBER_SEARCH_COLUMN_SUMMARY",
        "UBER_SEARCH_PROPERTY_SUMMARY",
        "UBER_SEARCH_TABLES",
        "DOWNLOAD_DATA_LAKE_QUERY",
        "DOWNLOAD_UBER_SEARCH_QUERY",
        "CANCEL_DATA_LAKE_QUERY",
        "CANCEL_UBER_SEARCH"
    }

    def rule(self, event):
        action = event.get("actionName")
        return action in self.SEARCH_OPERATIONS

    tests = [
        RuleTest(
            name="Data Lake Query Execution",
            expected_result=True,
            log={
                "actionName": "EXECUTE_DATA_LAKE_QUERY",
                "userName": "analyst",
                "timestamp": "2024-02-07T00:00:00Z",
                "ipAddress": "192.0.2.1",
                "userAgent": "Mozilla/5.0",
                "success": True,
                "error": None,
                "requestParameters": {
                    "query": "SELECT * FROM data_lake.table LIMIT 10"
                }
            }
        ),
        RuleTest(
            name="Uber Search Execution",
            expected_result=True,
            log={
                "actionName": "EXECUTE_UBER_SEARCH",
                "userName": "analyst",
                "timestamp": "2024-02-07T00:00:00Z",
                "ipAddress": "192.0.2.1",
                "userAgent": "Mozilla/5.0",
                "success": True,
                "error": None,
                "requestParameters": {
                    "searchTerm": "error"
                }
            }
        ),
        RuleTest(
            name="Non-search Operation",
            expected_result=False,
            log={
                "actionName": "CREATE_USER",
                "userName": "admin",
                "timestamp": "2024-02-07T00:00:00Z",
                "ipAddress": "192.0.2.1",
                "userAgent": "Mozilla/5.0",
                "success": True
            }
        )
    ] 