"""
Tests for scripts/deploy_sentinel_rules.py - all offline, mocked client.

The live ARM path (sentinel_client.py) is not exercised here: no workspace is
reachable in CI. These pin the body-building logic and the upload/verify flow.
"""

from unittest.mock import MagicMock

import pytest
import yaml

from deploy_sentinel_rules import (
    build_alert_rule_body,
    build_function_body,
    deploy,
    load_artifacts,
    parent_techniques,
    severity_from_level,
    tactics_from_tags,
)

PARSER_KQL = "Event\n| where Source == \"Microsoft-Windows-Sysmon\"\n| extend Image = 1\n"
RULE_KQL = "Sysmon\n| where EventID == 1 and Image endswith \"\\\\powershell.exe\"\n"


# -- pure builders -----------------------------------------------------------

def test_severity_maps_and_defaults():
    assert severity_from_level("high") == "High"
    assert severity_from_level("critical") == "High"      # Sentinel has no Critical
    assert severity_from_level("medium") == "Medium"
    assert severity_from_level(None) == "Medium"
    assert severity_from_level("bogus") == "Medium"


def test_tactics_from_tags_excludes_techniques():
    tags = ["attack.execution", "attack.t1059", "attack.t1059.001", "attack.defense_evasion"]
    assert tactics_from_tags(tags) == ["Execution", "DefenseEvasion"]


def test_parent_techniques_strips_subs_and_dedupes():
    assert parent_techniques(["T1059", "T1059.001", "T1027"]) == ["T1027", "T1059"]
    assert parent_techniques([]) == []


def test_function_body_is_a_function():
    body = build_function_body("Sysmon", PARSER_KQL)
    props = body["properties"]
    assert props["functionAlias"] == "Sysmon"
    assert props["category"] == "Detection-as-Code"
    assert props["query"] == PARSER_KQL.strip()


def test_alert_rule_body_shape():
    sigma = {
        "title": "PowerShell Encoded Command",
        "description": "Detects encoded PowerShell.\n",
        "level": "medium",
        "tags": ["attack.execution", "attack.t1059", "attack.t1059.001"],
    }
    body = build_alert_rule_body(sigma, RULE_KQL, ["T1059", "T1059.001", "T1027"])
    assert body["kind"] == "Scheduled"
    props = body["properties"]
    assert props["displayName"] == "PowerShell Encoded Command"
    assert props["severity"] == "Medium"
    assert props["enabled"] is True
    assert props["query"] == RULE_KQL.strip()
    assert props["tactics"] == ["Execution"]
    assert props["techniques"] == ["T1027", "T1059"]
    assert props["triggerOperator"] == "GreaterThan"


# -- load_artifacts (synthetic repo) -----------------------------------------

@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setattr("deploy_sentinel_rules.REPO_ROOT", tmp_path)

    (tmp_path / "sentinel" / "parsers").mkdir(parents=True)
    (tmp_path / "sentinel" / "parsers" / "Sysmon.kql").write_text(PARSER_KQL, encoding="utf-8")

    sigma_dir = tmp_path / "rules" / "windows" / "execution"
    sigma_dir.mkdir(parents=True)
    (sigma_dir / "powershell_encoded_command.yml").write_text(
        yaml.safe_dump({
            "id": "a5c8d2e1-3f4b-5a6c-7d8e-9f0a1b2c3d4e",
            "title": "PowerShell Encoded Command",
            "description": "Detects encoded PowerShell.",
            "level": "medium",
            "tags": ["attack.execution", "attack.t1059", "attack.t1059.001"],
        }),
        encoding="utf-8",
    )

    out_q = tmp_path / "output" / "sentinel" / "windows" / "execution"
    out_q.mkdir(parents=True)
    (out_q / "powershell_encoded_command.kql").write_text(RULE_KQL, encoding="utf-8")

    map_path = tmp_path / "sentinel" / "rule_map.yml"
    map_path.write_text(
        yaml.safe_dump({
            "schema_version": "1.0",
            "parser": {"name": "Sysmon", "file": "sentinel/parsers/Sysmon.kql"},
            "rules": [
                {
                    "sigma_id": "a5c8d2e1-3f4b-5a6c-7d8e-9f0a1b2c3d4e",
                    "sigma_path": "rules/windows/execution/powershell_encoded_command.yml",
                    "kusto": "output/kusto/windows/execution/powershell_encoded_command.txt",
                    "techniques": ["T1059", "T1059.001", "T1027"],
                    "target": "parser",
                },
                {
                    "sigma_id": "0471bd9a-9b43-4f31-860f-4f8bf4950058",
                    "sigma_path": "rules/linux/credential_access/ssh_brute_force.yml",
                    "kusto": "output/kusto/linux/credential_access/ssh_brute_force.txt",
                    "techniques": ["T1110"],
                    "target": "unsupported",
                    "reason": "linux syslog",
                },
            ],
        }),
        encoding="utf-8",
    )
    return map_path, tmp_path / "output" / "sentinel"


def test_load_artifacts_parser_first_then_rules(repo):
    map_path, out_dir = repo
    arts = load_artifacts(map_path, out_dir)
    assert [a.kind for a in arts] == ["function", "rule"]   # parser precedes rules
    assert arts[0].id == "dac-parser-sysmon"
    assert arts[1].id == "a5c8d2e1-3f4b-5a6c-7d8e-9f0a1b2c3d4e"
    assert arts[1].body["properties"]["query"] == RULE_KQL.strip()


def test_load_artifacts_missing_query_raises(repo):
    map_path, out_dir = repo
    (out_dir / "windows" / "execution" / "powershell_encoded_command.kql").unlink()
    with pytest.raises(FileNotFoundError, match="generated query missing"):
        load_artifacts(map_path, out_dir)


# -- deploy flow (mocked client) ---------------------------------------------

def test_dry_run_never_touches_the_client(repo):
    map_path, out_dir = repo
    assert deploy(None, map_path, out_dir, dry_run=True) == 0


def test_deploy_puts_and_verifies(repo):
    map_path, out_dir = repo
    client = MagicMock()
    client.get_function_query.return_value = PARSER_KQL
    client.get_alert_rule_query.return_value = RULE_KQL

    assert deploy(client, map_path, out_dir) == 0

    client.deploy_function.assert_called_once()
    client.deploy_alert_rule.assert_called_once()
    # parser deployed before the rule
    assert client.deploy_function.call_args[0][0] == "dac-parser-sysmon"


def test_deploy_readback_mismatch_returns_1(repo):
    map_path, out_dir = repo
    client = MagicMock()
    client.get_function_query.return_value = "something else"

    assert deploy(client, map_path, out_dir) == 1
    # aborts on the parser mismatch, before ever deploying a rule
    client.deploy_alert_rule.assert_not_called()


def test_verify_only_reads_without_writing(repo):
    map_path, out_dir = repo
    client = MagicMock()
    client.get_function_query.return_value = PARSER_KQL
    client.get_alert_rule_query.return_value = RULE_KQL

    assert deploy(client, map_path, out_dir, verify_only=True) == 0

    client.deploy_function.assert_not_called()
    client.deploy_alert_rule.assert_not_called()


def test_verify_only_reports_absent(repo):
    map_path, out_dir = repo
    client = MagicMock()
    client.get_function_query.return_value = None   # not deployed yet
    client.get_alert_rule_query.return_value = None

    assert deploy(client, map_path, out_dir, verify_only=True) == 1
