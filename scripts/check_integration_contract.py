"""CI entrypoint for validating Hunter's machine-readable integration contract."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.doctor import HunterDoctor


def registered_functions() -> list[str]:
    import mcp_server
    return sorted(name for name, value in vars(mcp_server).items() if name.startswith("hunter_") and callable(value))


def main() -> int:
    result = HunterDoctor(ROOT, registered_functions(), config_paths=[]).contract_check()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
