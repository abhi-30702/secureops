import gc
import pytest
from unittest.mock import patch
from main import build_window


@pytest.fixture(autouse=True)
def _gc_after_each():
    yield
    gc.collect()


def test_build_window_returns_main_window(qapp):
    with patch("main.check_tools", return_value={}):
        from main_window import MainWindow
        win = build_window()
        assert isinstance(win, MainWindow)
        win.close()
