"""
Tests for scripts/wazuh_client.py

All offline: the HTTP session is an injected mock (ADTE's Wazuh-adapter test
pattern). Covers config parsing/guardrails, JWT auth + 401 re-auth, logtest
request construction + session-token reuse, rule upload, and readiness polling.
"""

import json
from unittest.mock import MagicMock

import pytest

from wazuh_client import (
    LogtestResult,
    WazuhClientError,
    WazuhConfig,
    WazuhManagerClient,
    _normalise_api_url,
)


# Generic RFC1918 address for tests - not any real lab host
VM = "https://10.0.0.10:55000"


def make_config(**overrides) -> WazuhConfig:
    kwargs = {
        "base_url": VM,
        "user": "wazuh-wui",
        "password": "secret",
        "verify_ssl": False,
    }
    kwargs.update(overrides)
    return WazuhConfig(**kwargs)


def make_response(status=200, payload=None, text=""):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload if payload is not None else {}
    resp.text = text or json.dumps(payload or {})
    return resp


def auth_response(token="jwt-token-1"):
    return make_response(200, {"data": {"token": token}})


def make_client(config=None, **session_returns) -> tuple[WazuhManagerClient, MagicMock]:
    session = MagicMock()
    session.post.return_value = session_returns.pop("post", auth_response())
    if "request" in session_returns:
        session.request.return_value = session_returns.pop("request")
    client = WazuhManagerClient(config or make_config(), session=session)
    return client, session


# -- config & guardrails ------------------------------------------------------


def test_url_normalisation_variants():
    """Bare host, host:port, and full URL all normalise to scheme://host:port."""
    assert _normalise_api_url("10.0.0.10") == VM
    assert _normalise_api_url("10.0.0.10:55000") == VM
    assert _normalise_api_url("https://10.0.0.10") == VM
    assert _normalise_api_url("http://localhost:55001") == "http://localhost:55001"


@pytest.mark.parametrize(
    "bad_host",
    ["https://169.254.169.254:55000", "https://metadata.google.internal", "169.254.1.1"],
)
def test_ssrf_targets_rejected(bad_host):
    """Cloud metadata and link-local hosts are refused outright."""
    with pytest.raises(WazuhClientError):
        make_config(base_url=bad_host)


def test_bad_scheme_rejected():
    with pytest.raises(WazuhClientError):
        make_config(base_url="ftp://10.0.0.10")


def test_verify_ssl_false_allowed_for_private_hosts():
    """Self-signed lab certs: verify=False OK for RFC1918 and localhost."""
    assert make_config(base_url=VM, verify_ssl=False).verify_ssl is False
    assert make_config(base_url="localhost", verify_ssl=False).verify_ssl is False


def test_verify_ssl_false_refused_for_public_host():
    with pytest.raises(WazuhClientError):
        make_config(base_url="https://wazuh.example.com:55000", verify_ssl=False)


def test_from_env_reads_variables(monkeypatch):
    monkeypatch.setenv("DAC_WAZUH_API_HOST", "10.0.0.10")
    monkeypatch.setenv("DAC_WAZUH_API_USER", "wazuh-wui")
    monkeypatch.setenv("DAC_WAZUH_API_PASS", "pw")
    monkeypatch.setenv("DAC_WAZUH_API_VERIFY_SSL", "false")

    config = WazuhConfig.from_env()

    assert config.base_url == VM
    assert config.user == "wazuh-wui"
    assert config.verify_ssl is False


def test_from_env_requires_credentials(monkeypatch):
    monkeypatch.delenv("DAC_WAZUH_API_USER", raising=False)
    monkeypatch.delenv("DAC_WAZUH_API_PASS", raising=False)
    with pytest.raises(WazuhClientError, match="DAC_WAZUH_API_USER"):
        WazuhConfig.from_env()


def test_password_masked_in_repr():
    config = make_config(password="hunter2")
    assert "hunter2" not in repr(config)


# -- authentication -----------------------------------------------------------


def test_authenticate_posts_basic_auth_and_stores_jwt():
    client, session = make_client()

    client.authenticate()

    args, kwargs = session.post.call_args
    assert args[0] == f"{VM}/security/user/authenticate"
    assert kwargs["auth"] == ("wazuh-wui", "secret")
    assert client._jwt == "jwt-token-1"


def test_authenticate_raises_on_bad_credentials():
    client, session = make_client(post=make_response(401, text="unauthorized"))
    with pytest.raises(WazuhClientError, match="check DAC_WAZUH_API_USER"):
        client.authenticate()


def test_expired_jwt_triggers_single_reauth():
    """A 401 mid-flight re-authenticates once, then retries the request."""
    client, session = make_client()
    session.post.side_effect = [auth_response("jwt-1"), auth_response("jwt-2")]
    session.request.side_effect = [
        make_response(401, text="expired"),
        make_response(200, {"data": {"ok": True}}),
    ]

    resp = client._send("GET", "/manager/status")

    assert resp.status_code == 200
    assert client._jwt == "jwt-2"
    assert session.post.call_count == 2
    # Retried request carries the refreshed token
    final_headers = session.request.call_args_list[-1].kwargs["headers"]
    assert final_headers["Authorization"] == "Bearer jwt-2"


def test_connection_error_wrapped_with_context():
    import requests as requests_lib

    client, session = make_client()
    session.request.side_effect = requests_lib.exceptions.ConnectionError("refused")

    with pytest.raises(WazuhClientError, match="Cannot reach Wazuh Manager API"):
        client._send("GET", "/")


# -- logtest ------------------------------------------------------------------


def logtest_response(rule_id="100100", level=12, token="sess-1", alert=True):
    output = {}
    if rule_id is not None:
        output = {
            "rule": {"id": rule_id, "level": level, "description": "DAC: test rule"},
            "decoder": {"name": "json"},
        }
    return make_response(200, {"data": {"token": token, "output": output, "alert": alert}})


def test_logtest_request_construction_and_parsing():
    client, session = make_client(request=logtest_response())

    result = client.logtest('{"win": {}}', log_format="json", location="EventChannel")

    method, url = session.request.call_args.args[:2]
    body = session.request.call_args.kwargs["json"]
    assert (method, url) == ("PUT", f"{VM}/logtest")
    assert body == {
        "token": "",
        "event": '{"win": {}}',
        "log_format": "json",
        "location": "EventChannel",
    }
    assert result == LogtestResult(
        rule_id="100100", level=12, description="DAC: test rule",
        decoder="json", alert=True, raw=result.raw,
    )


def test_logtest_session_token_reused_and_closed():
    client, session = make_client()
    session.request.side_effect = [
        logtest_response(token="sess-1"),
        logtest_response(token="sess-1"),
        make_response(200, {"data": {}}),  # DELETE
    ]

    client.logtest("e1")
    client.logtest("e2")
    client.close_logtest_session()

    second_body = session.request.call_args_list[1].kwargs["json"]
    assert second_body["token"] == "sess-1"
    delete_call = session.request.call_args_list[2]
    assert delete_call.args[:2] == ("DELETE", f"{VM}/logtest/sessions/sess-1")
    assert client._logtest_token is None


def test_logtest_no_match_yields_none_rule():
    """An event no rule matches must not crash - rule_id is None."""
    client, _ = make_client(request=logtest_response(rule_id=None, alert=False))

    result = client.logtest("benign noise")

    assert result.rule_id is None
    assert result.alert is False


def test_logtest_integer_rule_id_coerced_to_string():
    """Defensive: rule.id must come back as a string regardless of API typing."""
    client, _ = make_client(request=logtest_response(rule_id=100100))
    assert client.logtest("x").rule_id == "100100"


# -- rule deployment ----------------------------------------------------------


def test_upload_rule_file_puts_with_overwrite():
    client, session = make_client(
        request=make_response(200, {"data": {"total_affected_items": 1}})
    )

    client.upload_rule_file("dac_windows.xml", "<group/>")

    call = session.request.call_args
    assert call.args[:2] == ("PUT", f"{VM}/rules/files/dac_windows.xml")
    assert call.kwargs["params"] == {"overwrite": "true"}
    assert call.kwargs["data"] == b"<group/>"


def test_wait_until_ready_polls_until_analysisd_running(monkeypatch):
    monkeypatch.setattr("wazuh_client.time.sleep", lambda s: None)
    client, session = make_client()
    session.request.side_effect = [
        make_response(200, {"data": {"affected_items": [{"wazuh-analysisd": "stopped"}]}}),
        make_response(200, {"data": {"affected_items": [{"wazuh-analysisd": "running"}]}}),
    ]

    client.wait_until_ready(timeout=60)  # returns without raising

    assert session.request.call_count == 2


def test_wait_until_ready_times_out(monkeypatch):
    monkeypatch.setattr("wazuh_client.time.sleep", lambda s: None)
    ticks = iter(range(0, 1000, 10))
    monkeypatch.setattr("wazuh_client.time.monotonic", lambda: next(ticks))
    client, session = make_client(
        request=make_response(200, {"data": {"affected_items": [{"wazuh-analysisd": "stopped"}]}})
    )

    with pytest.raises(WazuhClientError, match="not ready"):
        client.wait_until_ready(timeout=30)
