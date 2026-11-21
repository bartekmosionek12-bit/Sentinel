"""Porównanie zapisanych obrazów dwóch przebiegów."""

from __future__ import annotations

from typing import Any


def compare_runs(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, str]]:
    changes: list[dict[str, str]] = []

    def add(kind: str, host: str, item: str, old: object = "", new: object = "") -> None:
        changes.append(
            {"kind": kind, "host": host, "item": item, "before": str(old), "after": str(new)}
        )

    old_hosts = set(before)
    new_hosts = set(after)
    for host in sorted(new_hosts - old_hosts):
        add("host_new", host, "host", new=after[host].get("name", host))
    for host in sorted(old_hosts - new_hosts):
        add("host_disappeared", host, "host", old=before[host].get("name", host))
    for host in sorted(old_hosts & new_hosts):
        old, new = before[host], after[host]
        for field in ("services", "technologies"):
            for item in sorted(set(new.get(field, [])) - set(old.get(field, []))):
                add(f"{field}_new", host, item, new=item)
            for item in sorted(set(old.get(field, [])) - set(new.get(field, []))):
                add(f"{field}_disappeared", host, item, old=item)
        old_headers = {
            f"{service}:{name}": value
            for service, headers in old.get("headers", {}).items()
            for name, value in headers.items()
        }
        new_headers = {
            f"{service}:{name}": value
            for service, headers in new.get("headers", {}).items()
            for name, value in headers.items()
        }
        for item in sorted(old_headers.keys() | new_headers.keys()):
            if old_headers.get(item) != new_headers.get(item):
                add(
                    "header_changed",
                    host,
                    item,
                    old_headers.get(item, ""),
                    new_headers.get(item, ""),
                )
        if old.get("state") != new.get("state"):
            add("state_changed", host, "state", old.get("state", ""), new.get("state", ""))
    return changes
