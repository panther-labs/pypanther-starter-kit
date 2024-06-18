from typing import Type

import pytest
from pypanther import PantherRule, registered_rules
from pypanther.cache import DATA_MODEL_CACHE
from pypanther.import_main import import_main

import_main()


@pytest.mark.parametrize("rule", registered_rules(), ids=lambda x: x.RuleID)
def test_rule(rule: Type[PantherRule]):
    results = rule.run_tests(DATA_MODEL_CACHE.data_model_of_logtype)
    for result in results:
        assert result.Passed
