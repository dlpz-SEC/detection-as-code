"""
Drift check: wazuh/rule_map.yml <-> wazuh/rules/*.xml <-> rules/**/*.yml.

Runs offline in CI (Unit Tests stage). If someone edits a Sigma rule, the
Wazuh XML, or the map without keeping the three consistent, this fails the
build - the map is the contract that makes hand-ported twins safe.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
RULE_MAP_PATH = REPO_ROOT / "wazuh" / "rule_map.yml"

TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


def load_rule_map() -> dict:
    with open(RULE_MAP_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_xml_rules(xml_path: Path) -> dict[str, dict]:
    """Parse a Wazuh rule file -> {rule_id: {level, mitre_ids}}."""
    root = ET.fromstring(xml_path.read_text(encoding="utf-8"))
    groups = [root] if root.tag == "group" else root.findall("group")
    rules = {}
    for group in groups:
        for rule in group.findall("rule"):
            mitre_ids = [m.text for m in rule.findall("./mitre/id")]
            rules[rule.get("id")] = {
                "level": int(rule.get("level")),
                "mitre_ids": mitre_ids,
            }
    return rules


def sigma_techniques(sigma_path: Path) -> set[str]:
    # safe_load_all: correlation rule files are multi-document (base rule +
    # correlation doc). Union the technique tags across every doc so a
    # correlation's techniques are not lost.
    with open(sigma_path, encoding="utf-8") as f:
        docs = [d for d in yaml.safe_load_all(f) if isinstance(d, dict)]
    techniques = set()
    for rule in docs:
        for tag in rule.get("tags", []) or []:
            m = TECHNIQUE_TAG_RE.match(str(tag))
            if m:
                techniques.add(m.group(1).upper())
    return techniques


@pytest.fixture(scope="module")
def rule_map() -> dict:
    return load_rule_map()


def test_map_exists_and_has_schema(rule_map):
    assert rule_map["schema_version"] == "1.0"
    assert rule_map["rules"], "rule_map.yml has no rules"


def test_all_ids_are_strings(rule_map):
    """String IDs end-to-end: the ADTE join key is alert rule.id (a string)."""
    for entry in rule_map["rules"]:
        for rid in entry["wazuh_rule_ids"] + entry["wazuh_suppression_ids"]:
            assert isinstance(rid, str), f"{entry['sigma_id']}: id {rid!r} is not a string"


def test_map_ids_exist_in_xml(rule_map):
    """Every mapped ID (alerting + suppression) exists in its XML file."""
    for entry in rule_map["rules"]:
        xml_rules = load_xml_rules(REPO_ROOT / entry["wazuh_file"])
        for rid in entry["wazuh_rule_ids"] + entry["wazuh_suppression_ids"]:
            assert rid in xml_rules, f"{rid} in map but not in {entry['wazuh_file']}"


def test_xml_ids_exist_in_map(rule_map):
    """Every rule in the XML is claimed by the map - no orphan rules."""
    mapped = set()
    xml_files = set()
    for entry in rule_map["rules"]:
        mapped.update(entry["wazuh_rule_ids"] + entry["wazuh_suppression_ids"])
        xml_files.add(entry["wazuh_file"])
    for xml_file in xml_files:
        for rid in load_xml_rules(REPO_ROOT / xml_file):
            assert rid in mapped, f"{rid} in {xml_file} but not in rule_map.yml"


def test_alerting_and_suppression_levels(rule_map):
    """Alerting rules have level > 0; suppression children are exactly 0."""
    for entry in rule_map["rules"]:
        xml_rules = load_xml_rules(REPO_ROOT / entry["wazuh_file"])
        for rid in entry["wazuh_rule_ids"]:
            assert xml_rules[rid]["level"] > 0, f"{rid} mapped as alerting but level 0"
        for rid in entry["wazuh_suppression_ids"]:
            assert xml_rules[rid]["level"] == 0, f"{rid} mapped as suppression but level > 0"


def test_sigma_ids_and_paths_agree(rule_map):
    """sigma_path exists and the YAML inside carries the mapped sigma_id."""
    for entry in rule_map["rules"]:
        sigma_path = REPO_ROOT / entry["sigma_path"]
        assert sigma_path.is_file(), f"missing Sigma file: {entry['sigma_path']}"
        # safe_load_all + any-doc match: a correlation rule file carries the
        # base rule and the correlation doc, each with its own id.
        with open(sigma_path, encoding="utf-8") as f:
            docs = [d for d in yaml.safe_load_all(f) if isinstance(d, dict)]
        ids = [d.get("id") for d in docs]
        assert entry["sigma_id"] in ids, (
            f"{entry['sigma_path']}: ids {ids} do not include map sigma_id {entry['sigma_id']}"
        )


def test_techniques_match_sigma_tags(rule_map):
    """Map techniques are exactly the technique tags of the Sigma rule."""
    for entry in rule_map["rules"]:
        expected = sigma_techniques(REPO_ROOT / entry["sigma_path"])
        assert set(entry["techniques"]) == expected, (
            f"{entry['sigma_id']}: map techniques {entry['techniques']} "
            f"!= Sigma tags {sorted(expected)}"
        )


def test_xml_mitre_matches_map(rule_map):
    """Alerting XML rules carry exactly the mapped MITRE technique IDs."""
    for entry in rule_map["rules"]:
        xml_rules = load_xml_rules(REPO_ROOT / entry["wazuh_file"])
        for rid in entry["wazuh_rule_ids"]:
            assert set(xml_rules[rid]["mitre_ids"]) == set(entry["techniques"]), (
                f"rule {rid}: XML mitre {xml_rules[rid]['mitre_ids']} "
                f"!= map techniques {entry['techniques']}"
            )


def test_every_production_sigma_rule_is_mapped(rule_map):
    """New production Sigma rules must get a Wazuh twin (or a conscious skip here)."""
    mapped_sigma_ids = {e["sigma_id"] for e in rule_map["rules"]}
    for sigma_path in (REPO_ROOT / "rules").rglob("*.yml"):
        # safe_load_all: correlation rule files are multi-document. Each doc is
        # checked independently, so a production correlation doc is held to the
        # same Wazuh-twin requirement as any other production rule.
        with open(sigma_path, encoding="utf-8") as f:
            docs = [d for d in yaml.safe_load_all(f) if isinstance(d, dict)]
        for rule in docs:
            custom = rule.get("custom") or {}
            if custom.get("lifecycle") == "production":
                assert rule.get("id") in mapped_sigma_ids, (
                    f"production rule {sigma_path.name} has no Wazuh twin in rule_map.yml"
                )
