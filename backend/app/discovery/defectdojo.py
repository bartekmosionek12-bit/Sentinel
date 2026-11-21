"""Eksport obserwacji do DefectDojo (API v2) jako findingi o ważności Info.

Używamy `/api/v2/import-scan/` z formatem „Generic Findings Import”: DefectDojo sam zakłada
produkt i engagement z konfiguracji (`auto_create_context`). Każdy finding ma
`unique_id_from_tool` (ip:port/protokół:rodzaj), a my dodatkowo pamiętamy wysłane
identyfikatory w `defectdojo_export`, więc ponowny eksport nie dubluje zgłoszeń.
Token jest tylko w `.env` (DEFECTDOJO_TOKEN); nie trafia do logów, audytu ani odpowiedzi API.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import date
from typing import Any

import httpx


@dataclass(frozen=True)
class DojoConfig:
    url: str
    token: str
    product: str
    product_type: str
    engagement: str

    @classmethod
    def from_env(cls) -> DojoConfig:
        return cls(
            url=os.environ.get("DEFECTDOJO_URL", "").rstrip("/"),
            token=os.environ.get("DEFECTDOJO_TOKEN", ""),
            product=os.environ.get("DEFECTDOJO_PRODUCT", "Sentinel ASI"),
            product_type=os.environ.get("DEFECTDOJO_PRODUCT_TYPE", "Research and Development"),
            engagement=os.environ.get("DEFECTDOJO_ENGAGEMENT", "Discovery"),
        )

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token)


def findings_for(host: dict[str, Any]) -> list[dict[str, Any]]:
    """Obserwacje hosta jako findingi Info: każda otwarta usługa i każda flaga osobno."""
    ip = host["ip"]
    name = host.get("hostname") or ip
    out: list[dict[str, Any]] = []
    for service in host.get("services", []):
        port, proto = int(service["port"]), service.get("protocol", "tcp")
        product = " ".join(p for p in (service.get("product"), service.get("version")) if p)
        out.append(
            {
                "title": f"Usługa {service.get('name') or '?'} {port}/{proto} na {name}",
                "severity": "Info",
                "description": f"Host {ip} ({name}) odpowiada na {port}/{proto}. "
                f"Usługa: {service.get('name') or '?'} {product}".strip(),
                "unique_id_from_tool": f"{ip}:{port}/{proto}:service",
                "vuln_id_from_tool": "sentinel-asi:service",
                "endpoints": [{"host": ip, "port": port, "protocol": proto}],
                "date": date.today().isoformat(),
            }
        )
    for flag in host.get("flags", []):
        out.append(
            {
                "title": f"{flag['label']} na {name}",
                "severity": "Info",
                "description": "Dowody (pewność: "
                + flag.get("confidence", "?")
                + "):\n- "
                + "\n- ".join(flag.get("evidence", [])),
                "unique_id_from_tool": f"{ip}:flag:{flag['kind']}",
                "vuln_id_from_tool": f"sentinel-asi:{flag['kind']}",
                "endpoints": [{"host": ip}],
                "date": date.today().isoformat(),
            }
        )
    return out


class DojoError(RuntimeError):
    pass


class DojoClient:
    def __init__(self, config: DojoConfig, client: httpx.Client | None = None) -> None:
        self._config = config
        self._client = client or httpx.Client(timeout=30, trust_env=False)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Token {self._config.token}"}

    def status(self) -> dict[str, Any]:
        if not self._config.configured:
            return {
                "configured": False,
                "ok": False,
                "detail": "Brak DEFECTDOJO_URL lub DEFECTDOJO_TOKEN w .env",
            }
        try:
            response = self._client.get(
                f"{self._config.url}/api/v2/user_contact_infos/?limit=1", headers=self._headers()
            )
        except httpx.HTTPError as error:
            return {
                "configured": True,
                "ok": False,
                "detail": f"Brak połączenia ({error.__class__.__name__})",
            }
        return {
            "configured": True,
            "ok": response.status_code == 200,
            "detail": "Połączono"
            if response.status_code == 200
            else f"HTTP {response.status_code}",
            "url": self._config.url,
            "product": self._config.product,
            "engagement": self._config.engagement,
        }

    def import_findings(self, findings: list[dict[str, Any]], *, test_title: str) -> dict[str, Any]:
        if not self._config.configured:
            raise DojoError("DefectDojo nie jest skonfigurowane (DEFECTDOJO_URL, DEFECTDOJO_TOKEN)")
        payload = json.dumps({"findings": findings}).encode()
        data = {
            "scan_type": "Generic Findings Import",
            "product_name": self._config.product,
            "product_type_name": self._config.product_type,
            "engagement_name": self._config.engagement,
            "test_title": test_title,
            "auto_create_context": "true",
            "minimum_severity": "Info",
            "active": "true",
            "verified": "false",
            "deduplication_on_engagement": "true",
        }
        try:
            response = self._client.post(
                f"{self._config.url}/api/v2/import-scan/",
                headers=self._headers(),
                data=data,
                files={"file": ("sentinel.json", payload, "application/json")},
            )
        except httpx.HTTPError as error:
            raise DojoError(f"Brak połączenia z DefectDojo ({error.__class__.__name__})") from error
        if response.status_code not in (200, 201):
            raise DojoError(
                f"DefectDojo odrzuciło import: HTTP {response.status_code} {response.text[:200]}"
            )
        body = response.json()
        return {
            "test": body.get("test"),
            "engagement": body.get("engagement"),
            "product": body.get("product"),
        }
