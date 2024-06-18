from pypanther import register

from rules.aws_rules import AwsRule1, AwsRule2, AwsRule3

register(
    [
        AwsRule1,
        AwsRule2,
        AwsRule3,
    ]
)
