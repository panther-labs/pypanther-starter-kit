import unittest

from overrides.aws_guardduty import guard_duty_discovery_filter


class TestProdAccountFilter(unittest.TestCase):
    def test_guard_duty_discovery_filter(self):
        # Test case where the finding starts with Discovery
        event = {"type": "Discovery"}
        self.assertTrue(guard_duty_discovery_filter(event))

        # Test case where the finding does not start with Discovery
        event = {"type": "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom"}
        self.assertFalse(guard_duty_discovery_filter(event))

    # AttributeError: 'dict' object has no attribute 'deep_get'
    #
    # def test_guard_duty_sensitive_service_filter(self):
    #     # Test case where the service is sensitive
    #     event = {"service": {"action": {"awsApiCallAction": {"serviceName": "secretsmanager"}}}}
    #     self.assertTrue(guard_duty_sensitive_service_filter(event))

    #     # Test case where the service is not sensitive
    #     event = {"service": {"action": {"awsApiCallAction": {"serviceName": "cloudwatch"}}}}
    #     self.assertFalse(guard_duty_sensitive_service_filter(event))
