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
        # Every 30m
        cron_expression="*/30 * * * *",
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


class SnowflakeExternalShareQuery(Query):
    id = "Snowflake.External.Shares"
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
        # Every Hour
        CronExpression="0 0 * * *",
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
