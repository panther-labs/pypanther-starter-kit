from pypanther import PantherLogType, get_panther_rules, register

from rules.my_first_custom_rule import MyFirstCustomRule

onboarded_log_types = [
    # replace with your log types
    PantherLogType.AWS_CloudTrail,
]

# register tells Panther which rules you want uploaded
# accepts a list of PantherRule's
register(
    # utility function to easily upload Panther provided rules you care about
    # you can filter by any rule attribute
    get_panther_rules(
        LogTypes=onboarded_log_types,
    )
)

# register also accepts individual PantherRule's
register(MyFirstCustomRule)
