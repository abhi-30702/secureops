from app import create_app, COOL_QSS


def test_create_app_returns_qapplication(qapp):
    from PyQt6.QtWidgets import QApplication
    app = create_app()
    assert isinstance(app, QApplication)


def test_create_app_idempotent(qapp):
    app1 = create_app()
    app2 = create_app()
    assert app1 is app2


def test_cool_qss_contains_background_color():
    assert "#F4F6F9" in COOL_QSS


def test_cool_qss_contains_accent_blue():
    assert "#3D5A80" in COOL_QSS
