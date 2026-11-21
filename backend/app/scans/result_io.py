"""Import wyników z JSON, CSV i nmap XML do wspólnego modelu hosta."""

from __future__ import annotations

import csv
import io
import json
from ipaddress import ip_address
from typing import Any

from app.scanners.models import HostScan, ServiceInfo
from app.scanners.nmap import parse_nmap_xml


def parse_results(text: str, format: str) -> list[HostScan]:
    if format == "xml":
        hosts = parse_nmap_xml(text)
    elif format == "csv":
        grouped: dict[str, list[dict[str, str]]] = {}
        for row in csv.DictReader(io.StringIO(text)):
            grouped.setdefault(str(row.get("ip") or ""), []).append(row)
        hosts = [
            HostScan(ip=ip, services=tuple(_service(row) for row in rows if row.get("port")))
            for ip, rows in grouped.items()
        ]
    elif format == "json":
        data: Any = json.loads(text)
        if isinstance(data, dict):
            data = data.get("hosts", data)
        if isinstance(data, dict):
            data = [{"ip": ip, **item} for ip, item in data.items()]
        if not isinstance(data, list):
            raise ValueError("JSON musi zawierać listę hostów")
        hosts = []
        for item in data:
            if not isinstance(item, dict):
                raise ValueError("Host JSON musi być obiektem")
            services = []
            for raw in item.get("services", []):
                if isinstance(raw, str):
                    protocol, port, product, version = (raw.split(":", 3) + [""] * 4)[:4]
                    raw = {
                        "protocol": protocol,
                        "port": port,
                        "product": product,
                        "version": version,
                    }
                services.append(_service(raw))
            hosts.append(
                HostScan(
                    ip=str(item.get("ip", "")),
                    hostname=item.get("hostname") or item.get("name"),
                    services=tuple(services),
                )
            )
    else:
        raise ValueError("Nieznany format wyników")
    if len(hosts) > 100_000:
        raise ValueError("Za dużo hostów")
    for host in hosts:
        ip_address(host.ip)
    return hosts


def _service(row: dict[str, Any]) -> ServiceInfo:
    port = int(row.get("port") or 0)
    if not 1 <= port <= 65535:
        raise ValueError("Port poza zakresem 1-65535")
    return ServiceInfo(
        port=port,
        protocol=str(row.get("protocol") or "tcp"),
        name=str(row.get("name") or ""),
        product=str(row.get("product") or ""),
        version=str(row.get("version") or ""),
    )
