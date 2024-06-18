from pypanther import register
from pypanther.rules.box_rules.box_policy_violation import (
    BoxContentWorkflowPolicyViolation,
)
from pypanther.wrap import exclude, include

from rules.no_asana_bullies import AsanaServiceAccountCreatedNoBullies

# include only accounts that are production
include(lambda e: e.get("env", "prod") == "prod")(BoxContentWorkflowPolicyViolation)

# exclude accounts that are for development
exclude(lambda e: e.get("env") == "dev")(BoxContentWorkflowPolicyViolation)

register(BoxContentWorkflowPolicyViolation)
register(AsanaServiceAccountCreatedNoBullies)
