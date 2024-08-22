import unittest

from overrides.aws_cloudtrail import prod_account_filter


class TestProdAccountFilter(unittest.TestCase):
    def test_prod_account_filter(self):
        # Test case where the account ID is in the list of production accounts
        event = {"recipientAccountId": "988776655444"}
        self.assertTrue(prod_account_filter(event))

        # Test case where the account ID is not in the list of production accounts
        event = {"recipientAccountId": "111111111111"}
        self.assertFalse(prod_account_filter(event))
