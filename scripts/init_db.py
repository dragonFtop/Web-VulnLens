from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import config  # noqa: E402
from app.db.database import init_db  # noqa: E402


def main() -> None:
    config.settings.ensure_dirs()
    init_db()
    print(f"数据库已初始化：{config.settings.db_path}")


if __name__ == "__main__":
    main()
