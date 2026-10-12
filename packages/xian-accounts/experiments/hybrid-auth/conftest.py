import pytest
from fixture_support import make_scenario


@pytest.fixture(scope="session")
def scenario():
    return make_scenario()
