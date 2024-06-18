from pypanther import PantherSeverity, register

# this does use the box_new_login in the v2 folder, because that is there just
# to make it easier to view the contents for this example
# instead this uses the pypanther provided rule BoxNewLogin
from pypanther.rules.box_rules.box_new_login import BoxNewLogin

# Override attributes on the upstream rule
BoxNewLogin.Severity = PantherSeverity.High
BoxNewLogin.Runbook = "Reach out to @security on Slack"

# Register the rule to upload it
register(BoxNewLogin)
