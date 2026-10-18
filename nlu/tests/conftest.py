from datetime import date

import pytest

from nlu.pipeline import NLUPipeline

REF = date(2026, 10, 15)  # a Thursday


@pytest.fixture(scope="session")
def pipe():
    return NLUPipeline(reference_date=REF)


@pytest.fixture(scope="session")
def rules_pipe():
    return NLUPipeline(ner_mode="rules_only", intent_mode="rules_only", reference_date=REF)
