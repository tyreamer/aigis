import pytest
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures"

collect_ignore_glob = ["fixtures/**"]


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR
