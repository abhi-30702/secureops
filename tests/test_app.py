from app import create_app, DARK_QSS


def test_create_app_returns_qapplication(qapp):
    from PyQt6.QtWidgets import QApplication
    app = create_app()
    assert isinstance(app, QApplication)


def test_create_app_idempotent(qapp):
    app1 = create_app()
    app2 = create_app()
    assert app1 is app2


def test_dark_qss_contains_background_color():
    assert "#0a0e1a" in DARK_QSS


def test_dark_qss_contains_accent_cyan():
    assert "#00d4ff" in DARK_QSS
