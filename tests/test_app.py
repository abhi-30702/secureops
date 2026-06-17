from app import create_app, CHIFFON_QSS


def test_create_app_returns_qapplication(qapp):
    from PyQt6.QtWidgets import QApplication
    app = create_app()
    assert isinstance(app, QApplication)


def test_create_app_idempotent(qapp):
    app1 = create_app()
    app2 = create_app()
    assert app1 is app2


def test_chiffon_qss_contains_background_color():
    assert "#FEFACD" in CHIFFON_QSS


def test_chiffon_qss_contains_accent_purple():
    assert "#5F4A8B" in CHIFFON_QSS
