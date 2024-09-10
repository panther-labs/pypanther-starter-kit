from abc import ABC

from croniter import croniter
from panther_core.enriched_event import PantherEvent
from pypanther import Rule, Severity


class Schedule:
    timeout_min: int
    cron_expression: str

    def __init__(self, cron_expression, timeout_mins):
        if not croniter.is_valid(cron_expression):
            raise ValueError(f"Invalid cron expression: {cron_expression}")
        self.cron_expression = cron_expression
        self.timeout_min = timeout_mins

    def __repr__(self):
        return f"PantherSchedule(CronExpression='{self.cron_expression}', TimeoutMinutes={self.timeout_min})"


class Query(ABC):
    id: str
    description: str
    _analysis_type = "QUERY"
    query: str
    params: dict = {}


class ScheduledRule(Rule, ABC):
    schedule: Schedule
    window_mins: int
    _analysis_type = "SCHEDULED_RULE"

    @ABC.abstractmethod
    def query(self) -> str:
        """PantherFlow or SQL query string to pull data for the rule"""
        raise NotImplementedError(
            "query() must be implemented as a PantherFlow or SQL expression in your ScheduledRule"
        )

    def rule(self, event: PantherEvent) -> bool:
        """Optional method to further filter the results of the query. Defaults to True to avoid redundant code."""
        return True


class OCSFBruteForceConnections(ScheduledRule):
    id = "OCSF.VPC.BruteForceConnections"
    enabled = True
    default_severity = Severity.LOW
    threshold = 5

    window_mins = 30
    schedule = Schedule(
        cron_expression="*/30 * * * *",  # Every 30m
        timeout_mins=5,
    )

    def query(self):
        return f"""
            panther_logs.public.ocsf_networkactivity
            | where p_event_time > time.ago({self.window_mins}m)
            | where metadata.product.name == 'Amazon VPC'
            | where connection_info.direction == 'Inbound'
            | where activity_name == 'Refuse'
            | where dst_endpoint.port between 1 .. 1024
            | summarize Count=agg.count() by dst_endpoint.interface_uid
            | extend AboveThresh = Count >= {self.threshold}
            | where AboveThresh == true
        """

    def rule(self, row):
        return row.get("AboveThresh")

    def title(self, row):
        return f"Endpoint [{row.get('dst_endpoint.interface_uid')}] has high refused connections in the past 20m"


class SnowflakeDataExfil(ScheduledRule):
    id = "Snowflake.DataExfil"
    enabled = True
    default_severity = Severity.HIGH

    window_mins = 60 * 24  # 24 hours - Alluding to "lookback window"
    schedule = Schedule(
        cron_expression="* */12 * * *",  # Every 12 hours
        timeout_mins=15,
    )

    def query(self):
        return f"""
            panther_logs.public.signals
            | where p_event_time > time.ago({self.window_mins}m)
            | sequence
                e1=(p_rule_id="{SnowflakeTempStageCreated.id}")
                e2=(p_rule_id="{SnowflakeCopyIntoStorage.id}")
                e3=(p_rule_id="{SnowflakeFileDownloaded.id}")
            | match on("stage")
        """


class SnowflakeFileDownloaded(ScheduledRule):
    id = "Snowflake.FileDownloaded"
    description = "Query to detect Snowflake data being downloaded"
    enabled = True
    create_alert = False

    schedule = Schedule(
        cron_expression="* 17 * * *",
        timeout_mins=5,
    )

    query = """
    SELECT 
        user_name,
        role_name,
        start_time AS p_event_time,
        query_type,
        execution_status,
        regexp_substr(query_text, 'GET\\s+(\\$\\$|\\\')?@([a-zA-Z0-9_\\.]+)', 1, 1, 'i', 2) as stage,
        regexp_substr(query_text, 'GET\\s+(\\$\\$|\\\')?@([a-zA-Z0-9_\\./]+)(\\$\\$|\\\')?\\s', 1, 1, 'i', 2) as path,
        query_text
    FROM 
        SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
    WHERE 
        query_type = 'GET_FILES' 
        AND path IS NOT NULL 
        AND p_occurs_since('1 day')
        AND execution_status = 'SUCCESS'
    LIMIT 100
    """


class SnowflakeCopyIntoStorage(ScheduledRule):
    id = "Snowflake.CopyIntoStorage"
    description = "Query to detect Snowflake data being copied into storage"

    enabled = True
    create_alert = False

    schedule = Schedule(
        cron_expression="* 17 * * *",
        timeout_mins=5,
    )

    query = """
    SELECT 
        user_name,
        role_name,
        start_time AS p_event_time,
        query_type,
        execution_status,
        regexp_substr(query_text, 'COPY\\s+INTO\\s+(\\$\\$|\\\')?@([a-zA-Z0-9_\\.]+)', 1, 1, 'i', 2) as stage,
        regexp_substr(query_text, 'COPY\\s+INTO\\s+(\\$\\$|\\\')?@([a-zA-Z0-9_\\./]+)(\\$\\$|\\\')?\\s+FROM', 1, 1, 'i', 2) as path,
        query_text
    FROM 
        SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
    WHERE 
        query_type = 'UNLOAD' 
        AND stage IS NOT NULL 
        AND p_occurs_since('1 day')
        AND execution_status = 'SUCCESS'
    LIMIT 100
    """


class SnowflakeTempStageCreated(ScheduledRule):
    id = "Snowflake.TempStageCreated"
    description = "Query to detect Snowflake temporary stages created"

    enabled = True
    create_alert = False

    schedule = Schedule(
        cron_expression="* 17 * * *",
        timeout_mins=5,
    )

    query = """
    SELECT 
        user_name,
        role_name,
        start_time AS p_event_time,
        query_type,
        execution_status,
        regexp_substr(query_text, 'CREATE\\s+(OR\\s+REPLACE\\s+)?(TEMPORARY\\s+|TEMP\\s+)STAGE\\s+(IF\\s+NOT\\s+EXISTS\\s+)?([a-zA-Z0-9_\\.]+)', 1, 1, 'i', 4) as stage,
        query_text
    FROM 
        SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
    WHERE 
        query_type = 'CREATE' 
        AND stage IS NOT NULL 
        AND p_occurs_since('1 day') 
        AND execution_status = 'SUCCESS'
    LIMIT 100
    """


class SnowflakeExternalShareQuery(Query):
    id = "Snowflake.ExternalShares"
    description = "Query to detect Snowflake data transfers across cloud accounts"
    query = """
        SELECT 
            *
        FROM 
            snowflake.account_usage.data_transfer_history
        WHERE
            DATEDIFF(HOUR, start_time, CURRENT_TIMESTAMP) < 24
            AND start_time IS NOT NULL
            AND source_cloud IS NOT NULL
            AND target_cloud IS NOT NULL
            AND bytes_transferred > 0
    """


class SnowflakeExteralShare(ScheduledRule):
    id = "Snowflake.External.Shares"
    enabled = True
    schedule = Schedule(
        CronExpression="0 0 * * *",  # Every Hour
        TimeoutMinutes=2,
    )
    query = SnowflakeExternalShareQuery

    def title(event):
        return (
            "A data export has been initiated from source cloud "
            f"[{event.get('source_cloud','<SOURCE_CLOUD_NOT_FOUND>')}] "
            f"in source region [{event.get('source_region','<SOURCE_REGION_NOT_FOUND>')}] "
            f"to target cloud [{event.get('target_cloud','<TARGET_CLOUD_NOT_FOUND>')}] "
            f"in target region [{event.get('target_region','<TARGET_REGION_NOT_FOUND>')}] "
            f"with transfer type [{event.get('transfer_type','<TRANSFER_TYPE_NOT_FOUND>')}] "
            f"for [{event.get('bytes_transferred','<BYTES_NOT_FOUND>')}] bytes."
        )
