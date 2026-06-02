import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from db import DB


@pytest.fixture
def db():
    return DB(":memory:")
