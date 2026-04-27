import os
import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(TESTS_DIR)


@pytest.fixture
def sample_rule_path():
    return os.path.join(TESTS_DIR, "fixtures", "sample_rule.json")


@pytest.fixture
def fixtures_dir():
    return os.path.join(TESTS_DIR, "fixtures")
