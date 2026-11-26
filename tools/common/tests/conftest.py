import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _fresh_guard():
    import profile_guard

    profile_guard._warned.clear()
    yield
    profile_guard._warned.clear()
