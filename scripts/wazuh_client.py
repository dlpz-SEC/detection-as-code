#!/usr/bin/env python3
"""
Wazuh Manager API client for functional detection testing.

Talks to the Wazuh Manager API (default port 55000) to run detection
verification through Wazuh's REAL analysis pipeline:

- JWT authentication (POST /security/user/authenticate, ~900s tokens,
  transparent re-auth on 401)
- logtest (PUT /logtest): feeds a raw event through the live decoders and
  ruleset and reports which rule fired - the Tier-2 verification primitive
- custom rule file upload / readback / manager restart (deploy support)

This module is the one sanctioned shared import among pipeline scripts
(infrastructure, not pipeline logic). It reads configuration from process
environment only - callers that want .env support load dotenv in their own
main() so the library stays testable.

Environment variables:
    DAC_WAZUH_API_HOST        host, host:port, or full URL (default port 55000)
    DAC_WAZUH_API_USER        Manager API user (required)
    DAC_WAZUH_API_PASS        Manager API password (required)
    DAC_WAZUH_API_VERIFY_SSL  "false" to skip TLS verification - allowed only
                              for localhost/RFC1918 lab hosts (default "true")
"""

import argparse
import ipaddress
import json
import os
import sys
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import requests
import urllib3


DEFAULT_API_PORT = 55000
REQUEST_TIMEOUT = 30  # seconds, matches ADTE's Wazuh adapter convention

# Hosts that must never be targets (cloud metadata endpoints)
_BLOCKED_HOSTS = {"169.254.169.254", "100.100.100.200", "metadata.google.internal"}


class WazuhClientError(Exception):
    """Raised for auth, transport, or API-level failures."""


def _normalise_api_url(raw: str) -> str:
    """Accept 'host', 'host:port', or a full URL; return 'https://host:port'."""
    raw = raw.strip()
    if not raw:
        raise WazuhClientError("Wazuh API host is empty")

    if "://" not in raw:
        raw = f"https://{raw}"

    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise WazuhClientError(f"Unsupported URL scheme: {parsed.scheme!r}")
    if not parsed.hostname:
        raise WazuhClientError(f"Could not parse host from {raw!r}")

    port = parsed.port or DEFAULT_API_PORT
    return f"{parsed.scheme}://{parsed.hostname}:{port}"


def _host_of(url: str) -> str:
    return urlparse(url).hostname or ""


def _is_private_or_local(host: str) -> bool:
    """True for localhost or RFC1918 addresses (the lab boundary)."""
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False  # hostname, not an IP - treat as non-local


def _validate_api_url(url: str) -> None:
    """Reject SSRF-style targets: metadata endpoints and link-local ranges."""
    host = _host_of(url)
    if host in _BLOCKED_HOSTS:
        raise WazuhClientError(f"Refusing blocked host: {host}")
    try:
        if ipaddress.ip_address(host) in ipaddress.ip_network("169.254.0.0/16"):
            raise WazuhClientError(f"Refusing link-local host: {host}")
    except ValueError:
        pass  # not an IP literal


@dataclass
class WazuhConfig:
    """Connection settings for the Wazuh Manager API."""

    base_url: str
    user: str
    password: str = field(repr=False)  # never in repr/logs
    verify_ssl: bool = True

    def __post_init__(self) -> None:
        self.base_url = _normalise_api_url(self.base_url)
        _validate_api_url(self.base_url)
        if not self.verify_ssl and not _is_private_or_local(_host_of(self.base_url)):
            # The manager ships a self-signed cert, so labs need verify=False,
            # but a public host with TLS off is a credential leak waiting to happen
            raise WazuhClientError(
                "DAC_WAZUH_API_VERIFY_SSL=false is only allowed for "
                "localhost/private (RFC1918) hosts"
            )

    @classmethod
    def from_env(cls) -> "WazuhConfig":
        host = os.environ.get("DAC_WAZUH_API_HOST", f"https://localhost:{DEFAULT_API_PORT}")
        user = os.environ.get("DAC_WAZUH_API_USER")
        password = os.environ.get("DAC_WAZUH_API_PASS")
        if not user or not password:
            raise WazuhClientError(
                "DAC_WAZUH_API_USER and DAC_WAZUH_API_PASS must be set "
                "(put them in .env - see .env.example)"
            )
        verify = os.environ.get("DAC_WAZUH_API_VERIFY_SSL", "true").lower() != "false"
        return cls(base_url=host, user=user, password=password, verify_ssl=verify)


@dataclass
class LogtestResult:
    """Outcome of one logtest call: which rule (if any) won for the event."""

    rule_id: Optional[str]
    level: Optional[int]
    description: Optional[str]
    decoder: Optional[str]
    alert: bool
    raw: dict = field(repr=False)


class WazuhManagerClient:
    """Thin client over the Wazuh Manager REST API (JWT + JSON)."""

    def __init__(self, config: WazuhConfig, session: Optional[requests.Session] = None):
        self._config = config
        self._session = session if session is not None else requests.Session()
        self._jwt: Optional[str] = None
        self._logtest_token: Optional[str] = None

    # -- transport ----------------------------------------------------------

    def _send(self, method: str, path: str, *, retry_auth: bool = True, **kwargs) -> requests.Response:
        if self._jwt is None:
            self.authenticate()

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._jwt}"

        with warnings.catch_warnings():
            if not self._config.verify_ssl:
                warnings.filterwarnings(
                    "ignore", category=urllib3.exceptions.InsecureRequestWarning
                )
            try:
                resp = self._session.request(
                    method,
                    f"{self._config.base_url}{path}",
                    headers=headers,
                    verify=self._config.verify_ssl,
                    timeout=REQUEST_TIMEOUT,
                    **kwargs,
                )
            except requests.exceptions.RequestException as e:
                raise WazuhClientError(
                    f"Cannot reach Wazuh Manager API at {self._config.base_url}: {e}"
                ) from e

        # JWT expires (~900s): re-authenticate once and retry
        if resp.status_code == 401 and retry_auth:
            self._jwt = None
            return self._send(method, path, retry_auth=False, **kwargs)

        if resp.status_code >= 400:
            raise WazuhClientError(
                f"{method} {path} failed: HTTP {resp.status_code}: {resp.text[:500]}"
            )
        return resp

    # -- auth ---------------------------------------------------------------

    def authenticate(self) -> None:
        """POST /security/user/authenticate with basic auth -> JWT."""
        with warnings.catch_warnings():
            if not self._config.verify_ssl:
                warnings.filterwarnings(
                    "ignore", category=urllib3.exceptions.InsecureRequestWarning
                )
            try:
                resp = self._session.post(
                    f"{self._config.base_url}/security/user/authenticate",
                    auth=(self._config.user, self._config.password),
                    verify=self._config.verify_ssl,
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.exceptions.RequestException as e:
                raise WazuhClientError(
                    f"Cannot reach Wazuh Manager API at {self._config.base_url}: {e}"
                ) from e

        if resp.status_code == 401:
            raise WazuhClientError("Authentication failed: check DAC_WAZUH_API_USER/PASS")
        if resp.status_code >= 400:
            raise WazuhClientError(
                f"Authentication failed: HTTP {resp.status_code}: {resp.text[:500]}"
            )

        token = resp.json().get("data", {}).get("token")
        if not token:
            raise WazuhClientError(f"No token in auth response: {resp.text[:500]}")
        self._jwt = token

    # -- logtest (the Tier-2 primitive) --------------------------------------

    def logtest(self, event: str, log_format: str = "json", location: str = "EventChannel") -> LogtestResult:
        """
        Run one event through the live decoders+rules; return the winning rule.

        Reuses a logtest session token across calls (analysisd keeps related
        state per session); call close_logtest_session() when done.
        """
        body = {
            "token": self._logtest_token or "",
            "event": event,
            "log_format": log_format,
            "location": location,
        }
        resp = self._send("PUT", "/logtest", json=body)
        data = resp.json().get("data", {})

        # Capture/refresh the session token for subsequent calls
        session_token = data.get("token")
        if session_token:
            self._logtest_token = session_token

        output = data.get("output") or {}
        rule = output.get("rule") or {}
        decoder = output.get("decoder") or {}
        rule_id = rule.get("id")

        return LogtestResult(
            rule_id=str(rule_id) if rule_id is not None else None,
            level=rule.get("level"),
            description=rule.get("description"),
            decoder=decoder.get("name"),
            alert=bool(data.get("alert", False)),
            raw=data,
        )

    def close_logtest_session(self) -> None:
        """DELETE /logtest/sessions/{token}; safe to call when no session exists."""
        if not self._logtest_token:
            return
        try:
            self._send("DELETE", f"/logtest/sessions/{self._logtest_token}")
        except WazuhClientError:
            pass  # best-effort cleanup - sessions expire server-side anyway
        finally:
            self._logtest_token = None

    # -- rule deployment ------------------------------------------------------

    def upload_rule_file(self, filename: str, content: str) -> dict:
        """PUT /rules/files/{filename}?overwrite=true with the XML body."""
        resp = self._send(
            "PUT",
            f"/rules/files/{filename}",
            params={"overwrite": "true"},
            data=content.encode("utf-8"),
            headers={"Content-Type": "application/octet-stream"},
        )
        return resp.json()

    def get_rule_file(self, filename: str) -> str:
        """GET /rules/files/{filename}?raw=true -> file content for byte-verify."""
        resp = self._send("GET", f"/rules/files/{filename}", params={"raw": "true"})
        return resp.text

    def restart_manager(self) -> None:
        """PUT /manager/restart - loads newly uploaded rules."""
        self._send("PUT", "/manager/restart")

    def wait_until_ready(self, timeout: int = 120, interval: int = 5) -> None:
        """Poll GET /manager/status until analysisd reports running."""
        deadline = time.monotonic() + timeout
        last_error = "no status yet"
        while time.monotonic() < deadline:
            try:
                resp = self._send("GET", "/manager/status")
                items = resp.json().get("data", {}).get("affected_items", [])
                if items and items[0].get("wazuh-analysisd") == "running":
                    return
                last_error = f"analysisd status: {items[0] if items else 'unknown'}"
            except WazuhClientError as e:
                last_error = str(e)  # API itself restarts; keep polling
                self._jwt = None
            time.sleep(interval)
        raise WazuhClientError(f"Manager not ready after {timeout}s ({last_error})")


# -- smoke CLI (Phase 0 / diagnostics) ---------------------------------------


def main(argv: Optional[list[str]] = None) -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    except ImportError:
        pass  # dotenv optional for the CLI; env vars work regardless

    parser = argparse.ArgumentParser(description="Wazuh Manager API smoke checks")
    parser.add_argument("--check-auth", action="store_true", help="Authenticate and print API info")
    parser.add_argument("--logtest-event", help="Raw event string to run through logtest")
    parser.add_argument("--log-format", default="json", help="logtest log_format (default: json)")
    parser.add_argument("--location", default="EventChannel", help="logtest location (default: EventChannel)")
    args = parser.parse_args(argv)

    if not args.check_auth and not args.logtest_event:
        parser.error("nothing to do: pass --check-auth and/or --logtest-event")

    try:
        client = WazuhManagerClient(WazuhConfig.from_env())

        if args.check_auth:
            client.authenticate()
            resp = client._send("GET", "/")
            info = resp.json().get("data", {})
            print("=" * 60)
            print("WAZUH MANAGER API")
            print("=" * 60)
            print(f"✅ Authenticated to {info.get('title', 'Wazuh API')} "
                  f"v{info.get('api_version', '?')} (revision {info.get('revision', '?')})")

        if args.logtest_event:
            result = client.logtest(args.logtest_event, args.log_format, args.location)
            client.close_logtest_session()
            print("=" * 60)
            print("LOGTEST RESULT")
            print("=" * 60)
            print(f"decoder:     {result.decoder}")
            print(f"rule.id:     {result.rule_id}")
            print(f"rule.level:  {result.level}")
            print(f"description: {result.description}")
            print(f"alert:       {result.alert}")
            print("--- raw ---")
            print(json.dumps(result.raw, indent=2)[:2000])
    except WazuhClientError as e:
        print(f"❌ {e}")
        sys.exit(2)  # infra failure convention (0 ok / 1 detection / 2 infra)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    main()
