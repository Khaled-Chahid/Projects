from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any


def json_default(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, set):
        return sorted(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=json_default),
        encoding="utf-8",
    )


def normalize_policy_document(document: Any) -> dict[str, Any]:
    if isinstance(document, dict):
        return document
    if not document:
        return {}
    if isinstance(document, str):
        from urllib.parse import unquote

        decoded = unquote(document)
        try:
            parsed = json.loads(decoded)
        except json.JSONDecodeError:
            return {"_raw": decoded}
        return parsed if isinstance(parsed, dict) else {"_value": parsed}
    return {"_value": document}
