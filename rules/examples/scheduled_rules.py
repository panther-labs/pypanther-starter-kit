from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal, Optional

from croniter import croniter
from panther_core.enriched_event import PantherEvent
from pypanther import Rule, Severity


@dataclass
class Schedule:
    enabled: bool = True
    timeout_min: int = 5
    cron_expression: Optional[str] = None
    period: Optional[str] = None

    def __init__(self):
        if not croniter.is_valid(self.cron_expression):
            raise ValueError(f"Invalid cron expression: {self.cron_expression}")

    def __repr__(self):
        return f"Schedule(enabled={self.enabled}, timeout_min={self.timeout_min}, cron_expression='{self.cron_expression}', period='{self.period}')"


class Query(ABC):
    _analysis_type = "QUERY"
    description: str = ""
    query_type: Literal["PantherFlow", "SQL"]
    expression: str
    schedule: Schedule

    @property
    def id(self):
        return self.__class__.__name__

    @abstractmethod
    def validate(self):
        """Ensure search syntax is proper."""
        pass


@dataclass
class PantherFlowQuery(Query):
    query_type: Literal["PantherFlow"] = "PantherFlow"


@dataclass
class SQLQuery(Query):
    query_type: Literal["SQL"] = "SQL"


class ScheduledRule(Rule, ABC):
    _analysis_type = "SCHEDULED_RULE"
    query: Query
    window_secs: int
    window_mins: int
    window_hours: int
    window_days: int

    def rule(self, event: PantherEvent) -> bool:
        """Optional method to further filter the results of the query. Defaults to True to avoid redundant code."""
        return True

    def query(self) -> Query:
        """Return the query object to be executed."""
        return self.query


class OCSFBruteForceConnections(ScheduledRule):
    id = "OCSF.VPC.BruteForceConnections"
    enabled = True
    default_severity = Severity.MEDIUM
    threshold = 5
    window_mins = 30

    def query(self):
        return PantherFlowQuery(
            expression=f"""
	            panther_logs.public.ocsf_networkactivity
	            | where p_event_time > time.ago({self.window_mins}m)
	            | where metadata.product.name == 'Amazon VPC'
	            | where connection_info.direction == 'Inbound'
	            | where activity_name == 'Refuse'
	            | where dst_endpoint.port between 1 .. 1024
	            | summarize Count=agg.count() by dst_endpoint.interface_uid
	            | extend AboveThresh = Count >= {self.threshold}
	            | where AboveThresh == true
			      """,
            schedule=Schedule(period=f"{self.window_mins}m"),
        )

    def title(self, event):
        interface = event.get("dst_endpoint.interface_uid")
        return f"Endpoint [{interface}] has refused a high # of connections in the past {self.window_mins}m"


class SnowflakeBruteForceByUsername(ScheduledRule):
    id = "Snowflake.BruteForceByUsername"
    enabled = True
    default_severity = Severity.MEDIUM
    query = SQLQuery(
        expression="""
            SELECT
            user_name,
            reported_client_type,
            ARRAY_AGG(DISTINCT error_code) as error_codes,
            ARRAY_AGG(DISTINCT error_message) as error_messages,
            COUNT(event_id) AS counts
        FROM snowflake.account_usage.login_history
        WHERE
            DATEDIFF(HOUR, event_timestamp, CURRENT_TIMESTAMP) < 24
            AND event_type = 'LOGIN'
            AND error_code IS NOT NULL
        GROUP BY reported_client_type, user_name
        HAVING counts >=5;
        """,
        schedule=Schedule(period="1d"),
        description="Detect brute force via failed logins to Snowflake",
    )

    def title(self, event):
        return f"User [{event.get('user_name')}] surpassed the failed logins threshold of 5"


class SnowflakeBruteForceByUsername2(ScheduledRule):
    id = "Snowflake.BruteForceByUsername"
    enabled = True
    default_severity = Severity.MEDIUM
    window_hours = 24
    threshold = 12

    def query(self):
        return SQLQuery(
            description="Detect brute force failed logins to Snowflake",
            expression=f"""
				    SELECT
				        user_name,
				        reported_client_type,
				        ARRAY_AGG(DISTINCT error_code) as error_codes,
				        ARRAY_AGG(DISTINCT error_message) as error_messages,
				        COUNT(event_id) AS counts
				    FROM snowflake.account_usage.login_history
				    WHERE
				        DATEDIFF(HOUR, event_timestamp, CURRENT_TIMESTAMP) < {self.window_hours}
				        AND event_type = 'LOGIN'
				        AND error_code IS NOT NULL
				    GROUP BY reported_client_type, user_name
				    HAVING counts >={self.threshold};
				    """,
            schedule=Schedule(period=f"{self.window_hours}h"),
        )

    def title(self, event):
        user = event.get("user_name")
        return f"Snowflake User [{user}] had more than [{self.threshold}] failed logins"


SnowflakeBruteForceByUsername2.override(
    window_hours=12,
    threshold=15,
)


class SnowflakeDataExfil(ScheduledRule):
    id = "Snowflake.DataExfil"
    enabled = True
    default_severity = Severity.HIGH
    window_hours = 24

    def query(self):
        return PantherFlowQuery(
            expression=f"""
                panther_logs.public.signals
                | where p_event_time > time.ago({self.window_hours}h)
                | sequence
                    e1=(p_rule_id="{SnowflakeTempStageCreated.id}")
                    e2=(p_rule_id="{SnowflakeCopyIntoStorage.id}")
                    e3=(p_rule_id="{SnowflakeFileDownloaded.id}")
                | match on=("stage")
            """,
            schedule=Schedule(
                period=f"{self.window_hours}h",
                timeout_mins=15,
            ),
        )


class SnowflakeFileDownloaded(ScheduledRule):
    id = "Snowflake.FileDownloaded"
    description = "Query to detect Snowflake data being downloaded"
    enabled = True
    create_alert = False

    def query(self):
        return SQLQuery(
            expression="""
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
        LIMIT 100""",
            schedule=Schedule(
                cron_expression="* 17 * * *",
                timeout_mins=5,
            ),
        )


class SnowflakeCopyIntoStorage(ScheduledRule):
    id = "Snowflake.CopyIntoStorage"
    description = "Query to detect Snowflake data being copied into storage"

    enabled = True
    create_alert = False

    schedule = Schedule(
        cron_expression="* 17 * * *",
        timeout_mins=5,
    )

    def query(self):
        return """
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
