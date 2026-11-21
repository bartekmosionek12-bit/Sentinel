"""Eksport obserwacji wyłącznie do lokalnego DefectDojo z profilu Compose."""

from __future__ import annotations

import hashlib
import os
from typing import Any

import httpx

LOCAL_URL = "http://defectdojo-nginx:8080"


class DefectDojoError(Exception):
    pass


class DefectDojoClient:
    def __init__(self) -> None:
        if os.getenv("DEFECTDOJO_URL", LOCAL_URL).rstrip("/") != LOCAL_URL:
            raise DefectDojoError("Dozwolony jest wyłącznie lokalny DefectDojo z profilu Compose")
        token = os.getenv("DEFECTDOJO_API_TOKEN", "")
        self.product_id = os.getenv("DEFECTDOJO_PRODUCT_ID", "")
        self.engagement_id = os.getenv("DEFECTDOJO_ENGAGEMENT_ID", "")
        self.test_id = os.getenv("DEFECTDOJO_TEST_ID", "")
        self.test_type_id: int | None = None
        if not all((token, self.product_id, self.engagement_id, self.test_id)):
            raise DefectDojoError("Brak lokalnego tokenu API albo ID product/engagement/test")
        self.client = httpx.Client(
            base_url=LOCAL_URL,
            timeout=10,
            trust_env=False,
            headers={"Authorization": f"Token {token}", "Accept": "application/json"},
        )

    def _get(self, path: str, **params: str) -> dict[str, Any]:
        try:
            response = self.client.get(path, params=params)
            response.raise_for_status()
            data: dict[str, Any] = response.json()
            return data
        except (httpx.HTTPError, ValueError) as error:
            raise DefectDojoError(f"DefectDojo API: {type(error).__name__}") from error

    def validate_profile(self) -> None:
        test = self._get(f"/api/v2/tests/{self.test_id}/")
        engagement = self._get(f"/api/v2/engagements/{self.engagement_id}/")
        self.test_type_id = int(test["test_type"])
        if (
            str(test.get("engagement")) != self.engagement_id
            or str(engagement.get("product")) != self.product_id
        ):
            raise DefectDojoError("ID test, engagement i product nie tworzą jednej ścieżki")

    def export_flag(self, host: str, flag: dict[str, Any]) -> str:
        if self.test_type_id is None:
            self.validate_profile()
        kind = str(flag.get("kind") or "observation")
        unique_id = hashlib.sha256(f"sentinel-asi:{host}:{kind}".encode()).hexdigest()
        existing = self._get("/api/v2/findings/", unique_id_from_tool=unique_id, test=self.test_id)
        if any(
            str(row.get("unique_id_from_tool")) == unique_id
            and str(row.get("test")) == self.test_id
            for row in existing.get("results", [])
        ):
            return "duplicate"
        payload = {
            "title": f"Sentinel ASI: {kind} ({host})",
            "description": "; ".join(map(str, flag.get("evidence") or [])) or kind,
            "severity": "Info",
            "numerical_severity": "S0",
            "test": int(self.test_id),
            "found_by": [self.test_type_id],
            "unique_id_from_tool": unique_id,
            "active": True,
            "verified": False,
        }
        try:
            response = self.client.post("/api/v2/findings/", json=payload)
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise DefectDojoError(f"DefectDojo API: {type(error).__name__}") from error
        return "created"
