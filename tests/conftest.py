import pytest

from dth.scenarios import build_all


@pytest.fixture(scope="session")
def scenarios():
    return build_all()
