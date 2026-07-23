import sys
from app import create_app
from tool_checker import check_tools
from main_window import MainWindow
from db import DB
from app_paths import resolve_data_dir, fix_ownership


def build_window() -> MainWindow:
    tool_results = check_tools()
    data_dir = resolve_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    db = DB(str(data_dir / "secureops.db"))
    # If we're root (sudo, for live capture), hand the files back to the user
    # so a later normal launch shares the same database.
    fix_ownership(data_dir)
    return MainWindow(tool_results, db=db)


def main():
    app = create_app(sys.argv)
    window = build_window()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
