"""Import i eksport wyników: JSON, CSV, nmap XML (import i eksport do DefectDojo)."""

from __future__ import annotations

import csv
import io
import json
from typing import Any
from xml.sax.saxutils import quoteattr

from app.scanners.nmap import parse_nmap_xml

CSV_COLUMNS = (
    "ip",
    "hostname",
    "port",
    "protocol",
    "service",
    "product",
    "version",
    "title",
    "technologies",
    "flags",
)


class ImportError_(ValueError):
    """Plik nie jest w obsługiwanym formacie."""


def parse_import(content: str, filename: str = "") -> list[dict[str, Any]]:
    """Zwraca listę hostów {ip, hostname, services[], http[]} z JSON, CSV albo nmap XML."""
    text = content.strip()
    if not text:
        raise ImportError_("Pusty plik")
    if text.startswith("<") or filename.endswith(".xml"):
        try:
            hosts = parse_nmap_xml(text)
        except Exception as error:  # ToolError z parsera
            raise ImportError_(f"Nieprawidłowy nmap XML: {error}") from error
        return [
            {
                "ip": h.ip,
                "hostname": h.hostname,
                "services": [
                    {
                        "port": s.port,
                        "protocol": s.protocol,
                        "name": s.name,
                        "product": s.product,
                        "version": s.version,
                    }
                    for s in h.services
                ],
                "http": [],
            }
            for h in hosts
        ]
    if text.startswith(("{", "[")):
        try:
            data = json.loads(text)
        except json.JSONDecodeError as error:
            raise ImportError_(f"Nieprawidłowy JSON: {error.msg}") from error
        items = data.get("hosts", data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise ImportError_('JSON: oczekiwano listy hostów albo {"hosts": [...]}')
        out = []
        for item in items:
            if not isinstance(item, dict) or not item.get("ip"):
                continue
            out.append(
                {
                    "ip": str(item["ip"]),
                    "hostname": item.get("hostname"),
                    "services": [
                        s for s in item.get("services", []) if isinstance(s, dict) and "port" in s
                    ],
                    "http": [
                        h for h in item.get("http", []) if isinstance(h, dict) and "port" in h
                    ],
                }
            )
        return out
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "ip" not in [f.strip().lower() for f in reader.fieldnames]:
        raise ImportError_(
            "CSV: wymagana kolumna ip (opcjonalnie hostname, port, protocol, service, product,"
            " version)"
        )
    by_ip: dict[str, dict[str, Any]] = {}
    for row in reader:
        row = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
        ip = row.get("ip")
        if not ip:
            continue
        host = by_ip.setdefault(
            ip, {"ip": ip, "hostname": row.get("hostname") or None, "services": [], "http": []}
        )
        if row.get("port", "").isdigit():
            host["services"].append(
                {
                    "port": int(row["port"]),
                    "protocol": row.get("protocol") or "tcp",
                    "name": row.get("service", ""),
                    "product": row.get("product", ""),
                    "version": row.get("version", ""),
                }
            )
    return list(by_ip.values())


def hosts_csv(hosts: list[dict[str, Any]]) -> str:
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    for host in hosts:
        titles = {h["port"]: h.get("title", "") for h in host.get("http", [])}
        base = {
            "ip": host["ip"],
            "hostname": host.get("hostname") or "",
            "technologies": ";".join(host.get("technologies", [])),
            "flags": ";".join(f["kind"] for f in host.get("flags", [])),
        }
        services = host.get("services") or [{}]
        for service in services:
            writer.writerow(
                {
                    k: _safe(v)
                    for k, v in {
                        **base,
                        "port": service.get("port", ""),
                        "protocol": service.get("protocol", ""),
                        "service": service.get("name", ""),
                        "product": service.get("product", ""),
                        "version": service.get("version", ""),
                        "title": titles.get(service.get("port"), ""),
                    }.items()
                }
            )
    return out.getvalue()


def rows_csv(rows: list[dict[str, str]]) -> str:
    out = io.StringIO()
    if rows:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]))
        writer.writeheader()
        for row in rows:
            writer.writerow({k: _safe(v) for k, v in row.items()})
    return out.getvalue()


def _safe(value: Any) -> str:
    """Bez wstrzyknięcia formuł w arkuszu (=, +, -, @ na początku)."""
    text = "" if value is None else str(value)
    return f"'{text}" if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def nmap_xml(hosts: list[dict[str, Any]], *, started: int = 0) -> str:
    """Minimalny nmap XML (nmaprun) do importu parserem „Nmap Scan” w DefectDojo."""
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<nmaprun scanner="nmap" args="sentinel-asi discovery" start="{started}" version="7.95">',
    ]
    for host in hosts:
        lines.append('<host><status state="up" reason="sentinel"/>')
        lines.append(f'<address addr={quoteattr(host["ip"])} addrtype="ipv4"/>')
        if host.get("hostname"):
            lines.append(
                f'<hostnames><hostname name={quoteattr(host["hostname"])} type="user"/></hostnames>'
            )
        lines.append("<ports>")
        for s in host.get("services", []):
            lines.append(
                f'<port protocol={quoteattr(s.get("protocol", "tcp"))} portid="{int(s["port"])}">'
                '<state state="open" reason="syn-ack"/>'
                f"<service name={quoteattr(s.get('name', ''))} "
                f"product={quoteattr(s.get('product', ''))} "
                f"version={quoteattr(s.get('version', ''))}/></port>"
            )
        lines.append("</ports></host>")
    lines.append("</nmaprun>")
    return "\n".join(lines)
