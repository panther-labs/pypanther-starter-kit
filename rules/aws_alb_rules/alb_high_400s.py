from typing import Dict
from pypanther import PantherRule, PantherSeverity, PantherLogType, PantherRuleTest
from rules.aws_alb_rules.sample_logs import sample_alb_log


class AWSALBHighVol400s(PantherRule):
    RuleID = "AWS.ALB.HighVol400s"
    Enabled = False
    LogTypes = [PantherLogType.AWS_ALB]
    Severity = PantherSeverity.Medium
    # 10 matches per minute
    Threshold = 50
    DedupPeriodMinutes = 5
    Description = "This rule tracks abuse to web ports via AWS Load Balancers"
    Reports = {"MITRE ATT&CK": ["TA0010:T1499"]}  # Impact: Endpoint Denial of Service
    Runbook = (
        "Correlate the source IP to find matches from other triggered rules. "
        "Check which path is being requested to see if it is particularly sensitive. "
        "Check if the source IP is known bad through threat intelligence integrations. "
        "Check if the load balancer availability was affected. "
        "Check if the source IP is part of a known botnet. "
        "Check if this volume of 400 errors is typical or not for that load balancer. "
    )

    Tests = [
        PantherRuleTest(
            Name="ELB 400s, no domain",
            ExpectedResult=False,
            Log=sample_alb_log,
        ),
        PantherRuleTest(
            Name="ELB 400s, with a domain",
            ExpectedResult=True,
            Log=sample_alb_log | {"domainName": "example.com"},
        ),
        PantherRuleTest(
            Name="ELB 200s, with a domain",
            ExpectedResult=False,
            Log=sample_alb_log
            | {
                "domainName": "example.com",
                "elbStatusCode": 200,
                "targetStatusCode": 200,
            },
        ),
    ]

    # 429 Too Many Requests, 400 Bad Request, 403 Forbidden
    STATUS_CODES = {429, 400, 403}
    TARGET_WEB_PORTS = {80, 443, 4443, 8080}

    def rule(self, event) -> bool:
        return (
            # Use the target status code over elb status code because it represents the host's response
            event.get("targetStatusCode") in self.STATUS_CODES
            and event.get("targetPort") in self.TARGET_WEB_PORTS
            and event.get("domainName")
            is not None  # Ensure we have a domain name, but this could also check for valid domains
        )

    def title(self, event) -> str:
        domain_name = event.get("domainName")
        account_id = event.get("targetGroupArn").split(":")[4]
        return f"High volume of web port 4xx errors to [{domain_name}] in account [{account_id}]"

    def alert_context(self, event) -> Dict:
        return {
            "elb": event.get("elb"),
            "actionsExecuted": event.get("actionsExecuted"),
            "source_ip": event.udm("source_ip"),
            "target_port": event.get("targetPort"),
            "elb_status_code": event.get("elbStatusCode"),
            "target_status_code": event.get("targetStatusCode"),
            "user_agent": event.udm("user_agent"),
            "request_url": event.get("requestUrl"),
            "mitre_technique": "Endpoint Denial of Service",
            "mitre_tactic": "Impact",
        }
