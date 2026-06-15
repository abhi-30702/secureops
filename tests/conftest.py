import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt6.QtWidgets import QApplication
from db import DB


@pytest.fixture
def db():
    return DB(":memory:")


@pytest.fixture(autouse=True)
def process_events():
    """Flush pending Qt events after every test.

    This prevents dangling QThread signals / deferred deletions from
    leaking into the next test and causing a segfault inside
    pytestqt's _process_events during teardown.
    """
    yield
    app = QApplication.instance()
    if app is not None:
        app.processEvents()
