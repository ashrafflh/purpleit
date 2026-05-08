from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from purplestrike.models.simulation import SIEMAlert, SIEMRule

logger = logging.getLogger(__name__)


class WazuhConnector:
    """Wazuh SIEM connector via Management API."""

    name = "wazuh"

    def __init__(self) -> None:
        self._base_url = ""
        self._api_user = ""
        self._api_password = ""
        self._timeout = 30
        self._token: str | None = None
        self._client: httpx.AsyncClient | None = None

    async def setup(self, config: dict[str, Any]) -> None:
        import os

        self._base_url = config.get("api_url") or os.getenv("PURPLESTRIKE_WAZUH_API_URL", "")
        self._api_user = config.get("api_user") or os.getenv("PURPLESTRIKE_WAZUH_API_USER", "")
        self._api_password = config.get("api_password") or os.getenv("PURPLESTRIKE_WAZUH_API_PASSWORD", "")
        self._timeout = int(config.get("api_timeout", 0) or os.getenv("PURPLESTRIKE_WAZUH_API_TIMEOUT", "30"))

        if not self._base_url:
            raise ValueError("Wazuh API URL not configured. Set PURPLESTRIKE_WAZUH_API_URL.")

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout,
            verify=False,
        )

        await self._authenticate()

    async def _authenticate(self) -> None:
        if self._client is None:
            raise RuntimeError("Client not initialized")

        response = await self._client.post(
            "/security/user/auth",
            data={"username": self._api_user, "password": self._api_password},
        )
        response.raise_for_status()
        data = response.json()
        self._token = data["data"]["token"]

    async def _get_headers(self) -> dict[str, str]:
        if self._token is None:
            await self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    async def query_alerts(
        self,
        start_time: datetime,
        end_time: datetime,
        rule_ids: list[str] | None = None,
        source: str | None = None,
    ) -> list[SIEMAlert]:
        if self._client is None:
            return []

        headers = await self._get_headers()
        params: dict[str, Any] = {
            "time_from": start_time.strftime("%Y-%m-%dT%H:%M:%S"),
            "time_to": end_time.strftime("%Y-%m-%dT%H:%M:%S"),
            "limit": 500,
        }

        if rule_ids:
            params["rule.id"] = ",".join(rule_ids)
        if source:
            params["agent.name"] = source

        try:
            response = await self._client.get("/alerts", headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            return [self._parse_alert(a) for a in data.get("data", {}).get("affected_items", [])]
        except httpx.HTTPStatusError as e:
            logger.error(f"Wazuh API error querying alerts: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to query Wazuh alerts: {e}")
            return []

    async def get_rule(self, rule_id: str) -> SIEMRule | None:
        if self._client is None:
            return None

        headers = await self._get_headers()
        try:
            response = await self._client.get(f"/rules/{rule_id}", headers=headers)
            response.raise_for_status()
            data = response.json()
            items = data.get("data", {}).get("affected_items", [])
            if items:
                return self._parse_rule(items[0])
        except Exception as e:
            logger.error(f"Failed to get rule {rule_id}: {e}")
        return None

    async def get_rules_for_technique(self, technique_id: str) -> list[SIEMRule]:
        if self._client is None:
            return []

        headers = await self._get_headers()
        params: dict[str, Any] = {"limit": 500}
        if technique_id:
            params["mitre.id"] = technique_id

        try:
            response = await self._client.get("/rules", headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            return [self._parse_rule(r) for r in data.get("data", {}).get("affected_items", [])]
        except Exception as e:
            logger.error(f"Failed to get rules for technique {technique_id}: {e}")
            return []

    async def teardown(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        self._token = None

    def _parse_alert(self, raw: dict[str, Any]) -> SIEMAlert:
        rule_data = raw.get("rule", {})
        mitre_ids = []
        for m in rule_data.get("mitre", []):
            if isinstance(m, dict):
                mitre_ids.extend(m.get("id", []))
            elif isinstance(m, str):
                mitre_ids.append(m)

        return SIEMAlert(
            alert_id=str(raw.get("id", "")),
            timestamp=datetime.fromisoformat(raw.get("timestamp", datetime.now().isoformat())),
            rule_id=str(rule_data.get("id", "")),
            rule_description=rule_data.get("description", ""),
            severity=rule_data.get("level", ""),
            source=raw.get("agent", {}).get("name", ""),
            mitre_technique_ids=mitre_ids,
            raw_log=raw,
        )

    def _parse_rule(self, raw: dict[str, Any]) -> SIEMRule:
        mitre_ids = []
        for m in raw.get("mitre", []):
            if isinstance(m, dict):
                mitre_ids.extend(m.get("id", []))
            elif isinstance(m, str):
                mitre_ids.append(m)

        return SIEMRule(
            rule_id=str(raw.get("id", "")),
            description=raw.get("description", ""),
            severity=str(raw.get("level", "")),
            mitre_technique_ids=mitre_ids,
            rule_logic=raw.get("details", {}).get("text", "") if isinstance(raw.get("details"), dict) else "",
        )
