#!/usr/bin/env python3
"""
Azure Sentinel / Log Analytics ARM client for Detection-as-Code deployment.

Talks to the Azure Resource Manager REST API to push two kinds of artifact into
a Sentinel-enabled Log Analytics workspace:

- **Saved functions** (`savedSearches` with a `functionAlias`) — the `Sysmon`
  parser that re-materialises Event-table Sysmon rows into columns.
- **Scheduled analytics rules** (`Microsoft.SecurityInsights/alertRules`) — one
  per parser-fronted detection.

Mirrors wazuh_client.py: env-driven config, one custom exception, a thin
`requests` client, readback support so the deployer can verify before trusting.
The ARM and AAD hosts are constants (never user-controlled), so there is no
SSRF surface to guard as there is on the Wazuh side.

STATUS: built, live-UNVERIFIED — no workspace has been reachable to exercise it
against (no `az login` this session). Confirm at Phase 4 before trusting a green.

Token source (in order):
  1. Service principal, if DAC_SENTINEL_CLIENT_ID / _CLIENT_SECRET / _TENANT_ID
     are all set — OAuth2 client-credentials (works headless in CI).
  2. Otherwise `az account get-access-token` — uses the interactive `az login`.

Environment variables:
    DAC_SENTINEL_SUBSCRIPTION_ID   subscription GUID            (required)
    DAC_SENTINEL_RESOURCE_GROUP    resource group name          (required)
    DAC_SENTINEL_WORKSPACE_NAME    Log Analytics workspace name (required)
    DAC_SENTINEL_TENANT_ID         SP tenant   (optional; enables SP auth)
    DAC_SENTINEL_CLIENT_ID         SP app id   (optional; enables SP auth)
    DAC_SENTINEL_CLIENT_SECRET     SP secret   (optional; enables SP auth)
"""

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional

import requests

ARM_BASE = "https://management.azure.com"
ARM_RESOURCE = "https://management.azure.com"
AAD_HOST = "https://login.microsoftonline.com"

# API versions pinned so a service-side default bump can't silently change shapes.
SAVED_SEARCH_API_VERSION = "2020-08-01"
ALERT_RULE_API_VERSION = "2023-02-01"

REQUEST_TIMEOUT = 30  # seconds


class SentinelClientError(Exception):
    """Raised for auth, transport, or ARM API-level failures."""


@dataclass
class SentinelConfig:
    """Connection settings for the Sentinel workspace's ARM endpoints."""

    subscription_id: str
    resource_group: str
    workspace_name: str
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = field(default=None, repr=False)  # never in repr/logs

    @property
    def has_sp(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)

    @property
    def workspace_scope(self) -> str:
        return (
            f"/subscriptions/{self.subscription_id}"
            f"/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
        )

    @classmethod
    def from_env(cls) -> "SentinelConfig":
        sub = os.environ.get("DAC_SENTINEL_SUBSCRIPTION_ID")
        rg = os.environ.get("DAC_SENTINEL_RESOURCE_GROUP")
        ws = os.environ.get("DAC_SENTINEL_WORKSPACE_NAME")
        missing = [
            name
            for name, val in (
                ("DAC_SENTINEL_SUBSCRIPTION_ID", sub),
                ("DAC_SENTINEL_RESOURCE_GROUP", rg),
                ("DAC_SENTINEL_WORKSPACE_NAME", ws),
            )
            if not val
        ]
        if missing:
            raise SentinelClientError(
                f"missing required env vars: {', '.join(missing)} (see .env.example)"
            )
        return cls(
            subscription_id=sub,
            resource_group=rg,
            workspace_name=ws,
            tenant_id=os.environ.get("DAC_SENTINEL_TENANT_ID"),
            client_id=os.environ.get("DAC_SENTINEL_CLIENT_ID"),
            client_secret=os.environ.get("DAC_SENTINEL_CLIENT_SECRET"),
        )


def _token_via_sp(config: SentinelConfig, session: requests.Session) -> str:
    """OAuth2 client-credentials flow -> bearer token."""
    url = f"{AAD_HOST}/{config.tenant_id}/oauth2/v2.0/token"
    try:
        resp = session.post(
            url,
            data={
                "grant_type": "client_credentials",
                "client_id": config.client_id,
                "client_secret": config.client_secret,
                "scope": f"{ARM_RESOURCE}/.default",
            },
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        raise SentinelClientError(f"cannot reach AAD token endpoint: {e}") from e
    if resp.status_code >= 400:
        raise SentinelClientError(
            f"SP token request failed: HTTP {resp.status_code}: {resp.text[:300]}"
        )
    token = resp.json().get("access_token")
    if not token:
        raise SentinelClientError("no access_token in AAD response")
    return token


def _token_via_az_cli() -> str:
    """Shell out to `az account get-access-token` (uses the interactive login)."""
    az = shutil.which("az")
    if not az:
        raise SentinelClientError(
            "az CLI not found and no service principal configured — run `az login`, "
            "or set DAC_SENTINEL_TENANT_ID/CLIENT_ID/CLIENT_SECRET"
        )
    try:
        proc = subprocess.run(
            [az, "account", "get-access-token", "--resource", ARM_RESOURCE, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise SentinelClientError(f"az get-access-token failed to run: {e}") from e
    if proc.returncode != 0:
        raise SentinelClientError(
            f"az get-access-token failed (are you logged in?): {proc.stderr.strip()[:300]}"
        )
    import json

    try:
        return json.loads(proc.stdout)["accessToken"]
    except (ValueError, KeyError) as e:
        raise SentinelClientError(f"could not parse az token output: {e}") from e


class SentinelClient:
    """Thin client over the ARM REST API for Sentinel deployment artifacts."""

    def __init__(
        self,
        config: SentinelConfig,
        session: Optional[requests.Session] = None,
        token_provider: Optional[Callable[[], str]] = None,
    ):
        self._config = config
        self._session = session if session is not None else requests.Session()
        self._token_provider = token_provider
        self._token: Optional[str] = None

    # -- auth ---------------------------------------------------------------

    def _get_token(self) -> str:
        if self._token:
            return self._token
        if self._token_provider is not None:
            self._token = self._token_provider()
        elif self._config.has_sp:
            self._token = _token_via_sp(self._config, self._session)
        else:
            self._token = _token_via_az_cli()
        return self._token

    # -- transport ----------------------------------------------------------

    def _send(self, method: str, url: str, *, retry_auth: bool = True, **kwargs) -> requests.Response:
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._get_token()}"
        headers.setdefault("Content-Type", "application/json")
        try:
            resp = self._session.request(
                method, url, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs
            )
        except requests.exceptions.RequestException as e:
            raise SentinelClientError(f"cannot reach ARM at {url}: {e}") from e

        # Token expired: drop it, re-acquire once, retry.
        if resp.status_code == 401 and retry_auth:
            self._token = None
            return self._send(method, url, retry_auth=False, **kwargs)

        if resp.status_code >= 400:
            raise SentinelClientError(
                f"{method} {url.split('?')[0]} failed: HTTP {resp.status_code}: {resp.text[:500]}"
            )
        return resp

    def _url(self, resource_path: str, api_version: str) -> str:
        return f"{ARM_BASE}{self._config.workspace_scope}{resource_path}?api-version={api_version}"

    # -- saved function (the Sysmon parser) ---------------------------------

    def deploy_function(self, saved_search_id: str, body: dict) -> dict:
        """PUT a savedSearches function (parser). Returns the created resource."""
        url = self._url(f"/savedSearches/{saved_search_id}", SAVED_SEARCH_API_VERSION)
        return self._send("PUT", url, json=body).json()

    def get_function_query(self, saved_search_id: str) -> Optional[str]:
        """GET a savedSearches function's query for readback; None if absent."""
        url = self._url(f"/savedSearches/{saved_search_id}", SAVED_SEARCH_API_VERSION)
        try:
            resp = self._send("GET", url)
        except SentinelClientError:
            return None
        return (resp.json().get("properties") or {}).get("query")

    # -- scheduled analytics rule -------------------------------------------

    def deploy_alert_rule(self, rule_id: str, body: dict) -> dict:
        """PUT a Microsoft.SecurityInsights scheduled alert rule."""
        url = self._url(
            f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}",
            ALERT_RULE_API_VERSION,
        )
        return self._send("PUT", url, json=body).json()

    def get_alert_rule_query(self, rule_id: str) -> Optional[str]:
        """GET a scheduled rule's query for readback; None if absent."""
        url = self._url(
            f"/providers/Microsoft.SecurityInsights/alertRules/{rule_id}",
            ALERT_RULE_API_VERSION,
        )
        try:
            resp = self._send("GET", url)
        except SentinelClientError:
            return None
        return (resp.json().get("properties") or {}).get("query")
