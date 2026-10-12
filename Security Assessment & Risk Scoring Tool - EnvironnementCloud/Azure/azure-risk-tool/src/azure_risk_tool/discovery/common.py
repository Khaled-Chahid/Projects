from __future__ import annotations

import re
from typing import Any


def resource_group(resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    match = re.search(r"/resourceGroups/([^/]+)", resource_id, re.IGNORECASE)
    return match.group(1) if match else None


def normalize(items: list[dict[str, Any]], source: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in items:
        value = dict(item)
        value["resource_group"] = resource_group(value.get("id"))
        value["discovery_source"] = source
        result.append(value)
    return result
