from typing import Dict

from pypanther import LogType, Rule, RuleTest, Severity

from rules.examples.sample_logs import sample_alb_log

aws_alb_high_vol_400s_tests = [
    RuleTest(
        name="ELB 400s, no domain",
        expected_result=False,
        expected_title="High volume of web port 4xx errors to [None] in account [112233445566]",
        expected_alert_context={
            "elb": "app/web/22222f55555e618c",
            "actionsExecuted": ["forward"],
            "source_ip": None,
            "target_port": 80,
            "elb_status_code": 429,
            "target_status_code": 429,
            "user_agent": None,
            "request_url": "https://ec2-55-22-444-111.us-east-1.compute.amazonaws.com:443/pagekit/index.php",
            "mitre_technique": "Endpoint Denial of Service",
            "mitre_tactic": "Impact",
        },
        log=sample_alb_log,
    ),
    RuleTest(
        name="ELB 400s, with a domain",
        expected_result=True,
        expected_title="High volume of web port 4xx errors to [example.com] in account [112233445566]",
        expected_alert_context={
            "elb": "app/web/22222f55555e618c",
            "actionsExecuted": ["forward"],
            "source_ip": None,
            "target_port": 80,
            "elb_status_code": 429,
            "target_status_code": 429,
            "user_agent": None,
            "request_url": "https://ec2-55-22-444-111.us-east-1.compute.amazonaws.com:443/pagekit/index.php",
            "mitre_technique": "Endpoint Denial of Service",
            "mitre_tactic": "Impact",
        },
        log=sample_alb_log | {"domainName": "example.com"},
    ),
    RuleTest(
        name="ELB 200s, with a domain",
        expected_result=False,
        expected_title="High volume of web port 4xx errors to [example.com] in account [112233445566]",
        expected_alert_context={
            "elb": "app/web/22222f55555e618c",
            "actionsExecuted": ["forward"],
            "source_ip": None,
            "target_port": 80,
            "elb_status_code": 200,
            "target_status_code": 200,
            "user_agent": None,
            "request_url": "https://ec2-55-22-444-111.us-east-1.compute.amazonaws.com:443/pagekit/index.php",
            "mitre_technique": "Endpoint Denial of Service",
            "mitre_tactic": "Impact",
        },
        log=sample_alb_log
        | {
            "domainName": "example.com",
            "elbStatusCode": 200,
            "targetStatusCode": 200,
        },
    ),
]


class AWSALBHighVol400s(Rule):
    id = "AWS.ALB.HighVol400s"
    enabled = False
    log_types = [LogType.AWS_ALB]
    default_severity = Severity.MEDIUM
    # 10 matches per minute
    threshold = 50
    dedup_period_minutes = 5
    default_description = "This rule tracks abuse to web ports via AWS Load Balancers"
    reports = {"MITRE ATT&CK": ["TA0010:T1499"]}  # Impact: Endpoint Denial of Service
    default_runbook = (
        "Correlate the source IP to find matches from other triggered rules. "
        "Check which path is being requested to see if it is particularly sensitive. "
        "Check if the source IP is known bad through threat intelligence integrations. "
        "Check if the load balancer availability was affected. "
        "Check if the source IP is part of a known botnet. "
        "Check if this volume of 400 errors is typical or not for that load balancer. "
    )
    tests = aws_alb_high_vol_400s_tests

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
