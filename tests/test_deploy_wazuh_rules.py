"""
Tests for scripts/deploy_wazuh_rules.py - all offline, mocked client.
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from deploy_wazuh_rules import _normalise, deploy, load_rule_files


XML_CONTENT = '<group name="dac,">\n  <rule id="100100" level="12"/>\n</group>\n'


@pytest.fixture
def rule_map_setup(tmp_path, monkeypatch):
    """A miniature repo: rule_map.yml + the XML file it references."""
    monkeypatch.setattr("deploy_wazuh_rules.REPO_ROOT", tmp_path)
    xml_path = tmp_path / "wazuh" / "rules" / "dac_windows.xml"
    xml_path.parent.mkdir(parents=True)
    xml_path.write_text(XML_CONTENT, encoding="utf-8")

    map_path = tmp_path / "wazuh" / "rule_map.yml"
    map_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "1.0",
                "rules": [
                    {
                        "sigma_id": "abc",
                        "sigma_path": "rules/x.yml",
                        "techniques": ["T1003.001"],
                        "wazuh_file": "wazuh/rules/dac_windows.xml",
                        "wazuh_rule_ids": ["100100"],
                        "wazuh_suppression_ids": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return map_path


def test_load_rule_files_maps_basename_to_content(rule_map_setup):
    files = load_rule_files(rule_map_setup)
    assert files == {"dac_windows.xml": XML_CONTENT}


def test_load_rule_files_missing_xml_raises(rule_map_setup, tmp_path):
    (tmp_path / "wazuh" / "rules" / "dac_windows.xml").unlink()
    with pytest.raises(FileNotFoundError, match="dac_windows.xml"):
        load_rule_files(rule_map_setup)


def test_dry_run_never_touches_the_client(rule_map_setup):
    assert deploy(None, rule_map_setup, dry_run=True) == 0


def test_deploy_uploads_verifies_and_restarts(rule_map_setup):
    client = MagicMock()
    client.get_rule_file.return_value = XML_CONTENT

    assert deploy(client, rule_map_setup) == 0

    client.upload_rule_file.assert_called_once_with("dac_windows.xml", XML_CONTENT)
    client.get_rule_file.assert_called_once_with("dac_windows.xml")
    client.restart_manager.assert_called_once()
    client.wait_until_ready.assert_called_once()


def test_readback_mismatch_aborts_before_restart(rule_map_setup):
    client = MagicMock()
    client.get_rule_file.return_value = "<group>something else</group>"

    assert deploy(client, rule_map_setup) == 1

    client.restart_manager.assert_not_called()


def test_no_restart_uploads_only(rule_map_setup):
    client = MagicMock()
    client.get_rule_file.return_value = XML_CONTENT

    assert deploy(client, rule_map_setup, restart=False) == 0

    client.upload_rule_file.assert_called_once()
    client.restart_manager.assert_not_called()


def test_verify_only_reads_without_writing(rule_map_setup):
    client = MagicMock()
    client.get_rule_file.return_value = XML_CONTENT

    assert deploy(client, rule_map_setup, verify_only=True) == 0

    client.get_rule_file.assert_called_once()
    client.upload_rule_file.assert_not_called()
    client.restart_manager.assert_not_called()


def test_verify_only_reports_mismatch(rule_map_setup):
    client = MagicMock()
    client.get_rule_file.return_value = "<group>drifted</group>"

    assert deploy(client, rule_map_setup, verify_only=True) == 1


def test_normalise_is_line_ending_insensitive():
    assert _normalise("<a>\r\n</a>\r\n") == _normalise("<a>\n</a>\n")
