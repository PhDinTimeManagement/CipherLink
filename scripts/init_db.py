from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.app import build_services  # noqa: E402
from server.config import Settings  # noqa: E402


def main() -> None:
    settings = Settings.from_env()
    services = build_services(settings)
    print(f"Initialized database at {services.settings.db_path}")


if __name__ == "__main__":
    main()
