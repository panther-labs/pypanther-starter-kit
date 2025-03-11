from typing import Dict

from pypanther import LogType, Rule, RuleTest, Severity

sample_alb_log = {
    "actionsExecuted": ["forward"],
    "chosenCertArn": "arn:aws:acm:us-east-1:112233445566:certificate/77c83668-2cdd-4563-9d83-24bfd87fbbc0",
    "clientIp": "146.70.45.217",
    "clientPort": 42445,
    "connTraceId": "TID_02222c9aa077a44c66fade4aa3507f8d",
    "elb": "app/web/22222f55555e618c",
    "elbStatusCode": 429,
    "matchedRulePriority": 1,
    "receivedBytes": 424,
    "requestCreationTime": "2024-07-03 00:12:04.560000000",
    "requestHttpMethod": "GET",
    "requestHttpVersion": "HTTP/1.1",
    "requestProcessingTime": 0,
    "requestUrl": "https://ec2-55-22-444-111.us-east-1.compute.amazonaws.com:443/pagekit/index.php",
    "responseProcessingTime": 0,
    "sentBytes": 1787,
    "sslCipher": "ECDHE-RSA-AES128-GCM-SHA256",
    "sslProtocol": "TLSv1.2",
    "targetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:112233445566:targetgroup/web/22222f55555e618c",
    "targetIp": "10.0.0.12",
    "targetPort": 80,
    "targetPortList": ["10.0.0.12:80"],
    "targetProcessingTime": 0.001,
    "targetStatusCode": 429,
    "targetStatusList": ["429"],
    "timestamp": "2024-07-03 00:12:04.562175000",
    "traceId": "Root=1-66666654-5af8d57b17be5f6d0a0eb0ed",
    "type": "https",
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36",
}


class AWSALBHighVol400s(Rule):
    id = "AWS.ALB.HighVol400s"
    enabled = True
    log_types = [LogType.AWS_ALB]
    default_severity = Severity.MEDIUM
    threshold = 50  # 10 matches per minute
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

    tests = [
        RuleTest(
            name="ELB 400s, no domain",
            expected_result=False,
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
            log=sample_alb_log
            | {
                "domainName": "example.com",
                "elbStatusCode": 200,
                "targetStatusCode": 200,
            },
        ),
    ]
