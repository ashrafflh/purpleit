from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from purplestrike.models.simulation import SIEMAlert, SIEMRule

logger = logging.getLogger(__name__)


WAZUH_DASHBOARD_DEFAULT_USER = "admin"
WAZUH_DASHBOARD_HEADERS = {
    "osd-xsrf": "true",
    "kbn-xsrf": "true",
    "content-type": "application/json",
}


class WazuhConnector:
    """Wazuh SIEM connector via Management API."""

    name = "wazuh"

    def __init__(self) -> None:
        self._base_url = ""
        self._api_user = ""
        self._api_password = ""
        self._timeout = 30
        self._dashboard_url = ""
        self._dashboard_api_id = "default"
        self._token: str | None = None
        self._client: httpx.AsyncClient | None = None
        self._dashboard_client: httpx.AsyncClient | None = None
        self._all_rule_items: list[dict[str, Any]] | None = None

    async def setup(self, config: dict[str, Any]) -> None:
        import os

        self._all_rule_items = None

        nested_siem_config = config.get("siem")
        if "api_url" not in config and isinstance(nested_siem_config, dict):
            config = nested_siem_config

        self._base_url = config.get("api_url") or os.getenv("PURPLESTRIKE_WAZUH_API_URL", "")
        self._api_user = config.get("api_user") or os.getenv("PURPLESTRIKE_WAZUH_API_USER", "")
        self._api_password = config.get("api_password") or os.getenv(
            "PURPLESTRIKE_WAZUH_API_PASSWORD", ""
        )
        self._timeout = int(
            config.get("api_timeout", 0) or os.getenv("PURPLESTRIKE_WAZUH_API_TIMEOUT", "30")
        )
        extra = config.get("extra", {})
        if not isinstance(extra, dict):
            extra = {}
        self._dashboard_url = (
            config.get("dashboard_url")
            or extra.get("dashboard_url")
            or os.getenv("PURPLESTRIKE_WAZUH_DASHBOARD_URL", "")
            or self._derive_dashboard_url()
        )
        self._dashboard_api_id = (
            config.get("dashboard_api_id")
            or extra.get("dashboard_api_id")
            or os.getenv("PURPLESTRIKE_WAZUH_DASHBOARD_API_ID", "default")
        )

        if not self._base_url:
            raise ValueError("Wazuh API URL not configured. Set PURPLESTRIKE_WAZUH_API_URL.")

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            timeout=self._timeout,
            verify=False,
        )
        self._dashboard_client = httpx.AsyncClient(
            base_url=self._dashboard_url,
            timeout=self._timeout,
            verify=False,
            follow_redirects=True,
        )

        await self._authenticate()

    async def _authenticate(self) -> None:
        if self._client is None or self._dashboard_client is None:
            raise RuntimeError("Clients not initialized")

        token = await self._authenticate_via_dashboard()
        if not token:
            raise ValueError(self._invalid_credentials_message())
        self._token = token

    async def _authenticate_via_dashboard(self) -> str | None:
        if self._dashboard_client is None:
            raise RuntimeError("Dashboard client not initialized")

        login_response = await self._dashboard_client.post(
            "/auth/login",
            json={"username": self._api_user, "password": self._api_password},
            headers=WAZUH_DASHBOARD_HEADERS,
        )
        if login_response.status_code != 200:
            return None

        token_response = await self._dashboard_client.post(
            "/api/login",
            json={"idHost": self._dashboard_api_id, "force": True},
            headers=WAZUH_DASHBOARD_HEADERS,
        )
        if token_response.status_code != 200:
            return None
        return token_response.json().get("token")

    def _derive_dashboard_url(self) -> str:
        parsed = urlparse(self._base_url)
        return urlunparse((parsed.scheme, parsed.hostname or "", "", "", "", ""))

    def _invalid_credentials_message(self) -> str:
        return (
            f"Wazuh Dashboard authentication failed for user '{self._api_user}', "
            f"or dashboard API id '{self._dashboard_api_id}' did not issue a Wazuh API token. "
            f"The usual Wazuh Dashboard user is '{WAZUH_DASHBOARD_DEFAULT_USER}'. "
            "Update siem.api_user/siem.api_password in ~/.purplestrike/config.yaml, "
            "or set siem.dashboard_url/siem.dashboard_api_id if your dashboard host "
            "or API id differs."
        )

    async def _get_headers(self) -> dict[str, str]:
        if self._token is None:
            await self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    async def _request(
        self,
        method: str,
        endpoint: str,
        *,
        refresh_on_unauthorized: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        if self._client is None:
            raise RuntimeError("Client not initialized")

        headers = dict(kwargs.pop("headers", {}))
        headers.update(await self._get_headers())
        response = await self._client.request(method, endpoint, headers=headers, **kwargs)
        if response.status_code != 401 or not refresh_on_unauthorized:
            return response

        await self._authenticate()
        headers.update(await self._get_headers())
        return await self._client.request(method, endpoint, headers=headers, **kwargs)

    async def _dashboard_request(
        self,
        method: str,
        endpoint: str,
        *,
        refresh_on_unauthorized: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        if self._dashboard_client is None:
            raise RuntimeError("Dashboard client not initialized")

        headers = dict(kwargs.pop("headers", {}))
        headers.update(WAZUH_DASHBOARD_HEADERS)
        response = await self._dashboard_client.request(
            method,
            endpoint,
            headers=headers,
            **kwargs,
        )
        if response.status_code != 401 or not refresh_on_unauthorized:
            return response

        await self._authenticate()
        return await self._dashboard_client.request(method, endpoint, headers=headers, **kwargs)

    async def test_connection(self) -> dict[str, Any]:
        response = await self._request("GET", "/")
        response.raise_for_status()
        data = response.json()
        return data.get("data", data)

    async def query_alerts(
        self,
        start_time: datetime,
        end_time: datetime,
        rule_ids: list[str] | None = None,
        source: str | None = None,
    ) -> list[SIEMAlert]:
        if self._dashboard_client is None:
            raise RuntimeError("Wazuh Dashboard client is not initialized")

        time_range = {
            "gte": start_time.isoformat(),
            "lte": end_time.isoformat(),
            "format": "strict_date_optional_time",
        }
        # Manager and endpoint clocks can differ by more than the small query
        # padding. Retrieve Windows events by their occurrence time as well so
        # short steps do not disappear before validation sees their alerts.
        # The validation engine still enforces the exact event-time window,
        # excluding delayed events from earlier steps and cleanup.
        filters: list[dict[str, Any]] = [
            {
                "bool": {
                    "should": [
                        {"range": {"timestamp": time_range}},
                        {"range": {"data.win.system.systemTime": time_range}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        ]
        if rule_ids:
            filters.append({"terms": {"rule.id": [self._coerce_rule_id(r) for r in rule_ids]}})
        if source:
            filters.append(
                {
                    "bool": {
                        "should": [
                            {"term": {"agent.name": source}},
                            {"term": {"agent.ip": source}},
                            {"term": {"agent.id": source}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            )

        payload = {
            "params": {
                "index": "wazuh-alerts-*",
                "body": {
                    "size": 500,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "query": {"bool": {"filter": filters}},
                },
            }
        }

        alerts: list[SIEMAlert] = []
        while True:
            response = await self._dashboard_request(
                "POST",
                "/internal/search/opensearch",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            raw_response = data.get("rawResponse", {})
            if (data.get("isRunning") or data.get("isPartial")
                    or raw_response.get("timed_out")
                    or raw_response.get("_shards", {}).get("failed", 0)):
                raise RuntimeError("Wazuh returned an incomplete alert search")
            if "hits" not in raw_response or "hits" not in raw_response["hits"]:
                raise RuntimeError("Wazuh returned an invalid alert search response")
            hits = raw_response["hits"]["hits"]
            alerts.extend(self._parse_alert(hit.get("_source", hit)) for hit in hits)
            if len(hits) < 500:
                return alerts
            if len(alerts) >= 10000:
                raise RuntimeError("Wazuh alert search exceeded 10000 results; narrow the window")
            payload["params"]["body"]["from"] = len(alerts)

    async def get_rule(self, rule_id: str) -> SIEMRule | None:
        if self._client is None:
            return None

        try:
            response = await self._request("GET", "/rules", params={"rule_ids": rule_id})
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
        if self._all_rule_items is not None:
            return [self._parse_rule(rule) for rule in self._all_rule_items
                    if not technique_id or self._rule_matches_technique(rule, technique_id)]

        params: dict[str, Any] = {"limit": 500}
        if technique_id:
            params["mitre"] = technique_id

        try:
            items = await self._get_rule_items(params)
            if not technique_id:
                self._all_rule_items = items
        except httpx.HTTPStatusError as e:
            if technique_id and e.response.status_code >= 500:
                logger.warning(
                    "Wazuh rejected /rules mitre filter for %s; falling back to local filtering: %s",
                    technique_id,
                    e,
                )
                try:
                    items = await self._get_rule_items({"limit": 500})
                    self._all_rule_items = items
                except Exception as fallback_error:
                    logger.error(f"Failed to get rules for technique {technique_id}: {fallback_error}")
                    return []
            else:
                logger.error(f"Failed to get rules for technique {technique_id}: {e}")
                return []
        except Exception as e:
            logger.error(f"Failed to get rules for technique {technique_id}: {e}")
            return []

        if technique_id:
            items = [r for r in items if self._rule_matches_technique(r, technique_id)]
        return [self._parse_rule(r) for r in items]

    async def _get_rule_items(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        params = dict(params)
        while True:
            response = await self._request("GET", "/rules", params=params)
            response.raise_for_status()
            data = response.json().get("data", {})
            page = data.get("affected_items", [])
            items.extend(page)
            total = data.get("total_affected_items")
            if total is not None and len(items) >= total:
                return items
            if not page or (total is None and len(page) < params["limit"]):
                return items
            params["offset"] = len(items)

    async def teardown(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
        if self._dashboard_client:
            await self._dashboard_client.aclose()
            self._dashboard_client = None
        self._token = None
        self._all_rule_items = None

    def _parse_alert(self, raw: dict[str, Any]) -> SIEMAlert:
        rule_data = raw.get("rule", {})
        mitre_ids = self._extract_mitre_ids(rule_data.get("mitre", []))

        return SIEMAlert(
            alert_id=str(raw.get("id", "")),
            timestamp=datetime.fromisoformat(raw.get("timestamp", datetime.now().isoformat())),
            rule_id=str(rule_data.get("id", "")),
            rule_description=rule_data.get("description", ""),
            severity=str(rule_data.get("level", "")),
            source=raw.get("agent", {}).get("name", ""),
            mitre_technique_ids=mitre_ids,
            raw_log=raw,
        )

    def _parse_rule(self, raw: dict[str, Any]) -> SIEMRule:
        mitre_ids = self._extract_mitre_ids(raw.get("mitre", []))

        return SIEMRule(
            rule_id=str(raw.get("id", "")),
            description=raw.get("description", ""),
            severity=str(raw.get("level", "")),
            mitre_technique_ids=mitre_ids,
            rule_logic=(
                raw.get("details", {}).get("text", "")
                if isinstance(raw.get("details"), dict)
                else ""
            ),
        )

    def _rule_matches_technique(self, raw: dict[str, Any], technique_id: str) -> bool:
        mitre_ids = self._extract_mitre_ids(raw.get("mitre", []))
        return any(
            mitre_id == technique_id or mitre_id.startswith(f"{technique_id}.")
            for mitre_id in mitre_ids
        )

    def _extract_mitre_ids(self, raw_mitre: Any) -> list[str]:
        ids: list[str] = []

        def add(value: Any) -> None:
            if isinstance(value, str):
                ids.append(value)
            elif isinstance(value, list):
                for item in value:
                    add(item)

        if isinstance(raw_mitre, dict):
            add(raw_mitre.get("id", []))
        elif isinstance(raw_mitre, list):
            for item in raw_mitre:
                if isinstance(item, dict):
                    add(item.get("id", []))
                else:
                    add(item)
        else:
            add(raw_mitre)

        return ids

    def _coerce_rule_id(self, rule_id: str) -> int | str:
        return int(rule_id) if rule_id.isdigit() else rule_id
