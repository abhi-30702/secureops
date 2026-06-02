import sys
from pathlib import Path
from app import create_app
from tool_checker import check_tools
from main_window import MainWindow
from db import DB

_DB_PATH = Path.home() / ".secureops" / "secureops.db"


def build_window() -> MainWindow:
    tool_results = check_tools()
    _DB_PATH.parent.mkdir(exist_ok=True)
    db = DB(str(_DB_PATH))
    return MainWindow(tool_results, db=db)


def main():
    app = create_app(sys.argv)
    window = build_window()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
