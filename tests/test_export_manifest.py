"""
Tests for scripts/export_manifest.py

Covers production filtering, confidence weighting, MITRE technique tag
normalization, manifest metadata, idempotent writes, and edge cases
(malformed YAML, missing custom block, empty rule directories).
"""

import json
import re
from pathlib import Path

import pytest
import yaml

from export_manifest import (
    build_manifest,
    extract_rule_entry,
    extract_technique_tags,
    load_wazuh_rule_ids,
    main,
    write_manifest,
)


def make_rule(**overrides) -> dict:
    """Build a minimal valid production rule dict; overrides replace top-level keys."""
    rule = {
        "title": "Test Rule - Suspicious Activity",
        "id": "11111111-2222-3333-4444-555555555555",
        "status": "stable",
        "level": "high",
        "tags": ["attack.credential_access", "attack.t1003", "attack.t1003.001"],
        "custom": {
            "lifecycle": "production",
            "confidence": "high",
            "false_positive_rate": "low",
            "tuning_notes": "Tune per environment.",
        },
    }
    rule.update(overrides)
    return rule


def write_rule(rules_dir: Path, relpath: str, rule: dict) -> Path:
    """Write a rule dict as YAML under rules_dir, creating parent dirs."""
    rule_path = rules_dir / relpath
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    with open(rule_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(rule, f, sort_keys=False)
    return rule_path


def test_production_rule_included(tmp_path):
    """A rule at lifecycle: production appears in the manifest."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "windows/credential_access/test_rule.yml", make_rule())

    manifest = build_manifest(rules_dir)

    assert manifest["rule_count"] == 1
    entry = manifest["rules"][0]
    assert entry["id"] == "11111111-2222-3333-4444-555555555555"
    assert entry["title"] == "Test Rule - Suspicious Activity"
    assert entry["lifecycle"] == "production"
    assert entry["false_positive_rate"] == "low"
    assert entry["tuning_notes"] == "Tune per environment."


@pytest.mark.parametrize("lifecycle", ["experimental", "draft", "deprecated"])
def test_non_production_rules_excluded(tmp_path, lifecycle):
    """Rules at any non-production lifecycle are excluded."""
    rules_dir = tmp_path / "rules"
    rule = make_rule()
    rule["custom"]["lifecycle"] = lifecycle
    write_rule(rules_dir, "windows/execution/test_rule.yml", rule)

    manifest = build_manifest(rules_dir)

    assert manifest["rule_count"] == 0
    assert manifest["rules"] == []


def test_missing_custom_block_excluded(tmp_path):
    """A rule with no custom block has no lifecycle and is excluded."""
    rules_dir = tmp_path / "rules"
    rule = make_rule()
    del rule["custom"]
    write_rule(rules_dir, "windows/execution/no_custom.yml", rule)

    manifest = build_manifest(rules_dir)

    assert manifest["rules"] == []


@pytest.mark.parametrize(
    "confidence,weight",
    [("high", 1.0), ("medium", 0.6), ("low", 0.3)],
)
def test_confidence_weight_mapping(confidence, weight):
    """confidence_weight maps high=1.0, medium=0.6, low=0.3."""
    rule = make_rule()
    rule["custom"]["confidence"] = confidence

    entry = extract_rule_entry(rule, Path("rules/windows/r.yml"), Path("rules"))

    assert entry["confidence_weight"] == weight
    assert entry["confidence"] == confidence


def test_confidence_weight_defaults():
    """Missing or unknown confidence falls back to the 0.3 default weight."""
    missing = make_rule()
    del missing["custom"]["confidence"]
    entry = extract_rule_entry(missing, Path("rules/windows/r.yml"), Path("rules"))
    assert entry["confidence"] is None
    assert entry["confidence_weight"] == 0.3

    unknown = make_rule()
    unknown["custom"]["confidence"] = "critical"
    entry = extract_rule_entry(unknown, Path("rules/windows/r.yml"), Path("rules"))
    assert entry["confidence_weight"] == 0.3


def test_lifecycle_and_confidence_normalized():
    """Casing/whitespace in lifecycle and confidence is normalized, not dropped."""
    rule = make_rule()
    rule["custom"]["lifecycle"] = "  Production "
    rule["custom"]["confidence"] = "HIGH"

    entry = extract_rule_entry(rule, Path("rules/windows/r.yml"), Path("rules"))

    assert entry is not None  # not silently excluded over casing
    assert entry["lifecycle"] == "production"
    assert entry["confidence"] == "high"
    assert entry["confidence_weight"] == 1.0


def test_manifest_metadata(tmp_path):
    """The manifest carries schema_version 1.0 and an ISO-8601 UTC generated_at."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "windows/credential_access/test_rule.yml", make_rule())

    manifest = build_manifest(rules_dir)

    assert manifest["schema_version"] == "1.0"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", manifest["generated_at"])

    # Both fields survive the round-trip to the written file
    output = tmp_path / "docs" / "rule_manifest.json"
    write_manifest(manifest, output)
    with open(output, encoding="utf-8") as f:
        written = json.load(f)
    assert written["schema_version"] == "1.0"
    assert written["generated_at"] == manifest["generated_at"]


def test_technique_tags_normalized(tmp_path):
    """Technique tags are uppercased without the attack. prefix; tactics dropped."""
    rules_dir = tmp_path / "rules"
    rule = make_rule(
        tags=[
            "attack.credential_access",
            "attack.t1003",
            "attack.t1003.001",
            "attack.defense_evasion",
        ]
    )
    write_rule(rules_dir, "windows/credential_access/test_rule.yml", rule)

    manifest = build_manifest(rules_dir)

    assert manifest["rules"][0]["techniques"] == ["T1003", "T1003.001"]

    # Direct extraction: non-string tags skipped, duplicates deduped in order
    assert extract_technique_tags(
        ["attack.t1059.001", 42, "attack.t1059.001", "attack.execution", "attack.t1027"]
    ) == ["T1059.001", "T1027"]


def test_uppercase_technique_tags_normalized():
    """Non-standard uppercase tags (attack.T1003) are still captured."""
    assert extract_technique_tags(["attack.T1003.001", "attack.T1027"]) == [
        "T1003.001",
        "T1027",
    ]


def test_empty_or_missing_tags_do_not_crash(tmp_path):
    """An empty `tags:` key (parses to None) must not crash the export."""
    # Direct: non-list inputs yield no techniques rather than raising
    assert extract_technique_tags(None) == []
    assert extract_technique_tags("attack.t1003") == []

    rules_dir = tmp_path / "rules"
    rule = make_rule()
    rule["tags"] = None  # `tags:` with no value in YAML
    write_rule(rules_dir, "windows/execution/null_tags.yml", rule)

    manifest = build_manifest(rules_dir)

    assert manifest["rule_count"] == 1
    assert manifest["rules"][0]["techniques"] == []


def test_manifest_path_is_posix(tmp_path):
    """Manifest paths use forward slashes and are anchored at the rules dir name."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "windows/credential_access/test_rule.yml", make_rule())

    entry = build_manifest(rules_dir)["rules"][0]

    assert entry["path"] == "rules/windows/credential_access/test_rule.yml"
    assert "\\" not in entry["path"]


def test_rules_sorted_by_path(tmp_path):
    """Manifest entries are sorted by path for deterministic output."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "windows/zebra/z_rule.yml", make_rule(id="z" * 8, title="Z"))
    write_rule(rules_dir, "windows/alpha/a_rule.yml", make_rule(id="a" * 8, title="A"))

    paths = [entry["path"] for entry in build_manifest(rules_dir)["rules"]]

    assert paths == sorted(paths)
    assert paths[0] == "rules/windows/alpha/a_rule.yml"


def test_write_manifest_idempotent(tmp_path):
    """Same content with a newer timestamp does not rewrite the file."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "windows/credential_access/test_rule.yml", make_rule())
    output = tmp_path / "docs" / "rule_manifest.json"

    first = build_manifest(rules_dir)
    assert write_manifest(first, output) is True
    before = output.read_bytes()

    second = build_manifest(rules_dir)
    second["generated_at"] = "2099-01-01T00:00:00Z"  # simulate a later run
    assert write_manifest(second, output) is False
    assert output.read_bytes() == before


def test_write_manifest_detects_change(tmp_path):
    """Changed rule content rewrites the manifest."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "windows/credential_access/test_rule.yml", make_rule())
    output = tmp_path / "docs" / "rule_manifest.json"

    write_manifest(build_manifest(rules_dir), output)

    write_rule(
        rules_dir,
        "windows/execution/second_rule.yml",
        make_rule(id="22222222-3333-4444-5555-666666666666", title="Second Rule"),
    )
    assert write_manifest(build_manifest(rules_dir), output) is True

    with open(output, encoding="utf-8") as f:
        assert json.load(f)["rule_count"] == 2


def test_malformed_and_non_dict_yaml_skipped(tmp_path):
    """Malformed YAML and non-dict documents are skipped without crashing."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")
    (rules_dir / "list_root.yml").write_text("- just\n- a\n- list\n", encoding="utf-8")
    write_rule(rules_dir, "windows/valid_rule.yml", make_rule())

    manifest = build_manifest(rules_dir)

    assert manifest["rule_count"] == 1
    assert manifest["rules"][0]["path"] == "rules/windows/valid_rule.yml"


def test_duplicate_and_null_id_warn(tmp_path, capsys):
    """Duplicate or missing rule ids emit a warning (ADTE joins on id)."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "windows/a.yml", make_rule(id="shared-id"))
    write_rule(rules_dir, "windows/b.yml", make_rule(id="shared-id"))
    write_rule(rules_dir, "windows/c.yml", make_rule(id=None))

    build_manifest(rules_dir)

    out = capsys.readouterr().out
    assert "duplicate rule id" in out
    assert "no id" in out


def test_empty_rules_dir(tmp_path):
    """An empty rules dir produces a valid manifest with zero rules."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    manifest = build_manifest(rules_dir)

    assert manifest["rule_count"] == 0
    assert manifest["rules"] == []


def test_main_creates_output_dir_and_prints_summary(tmp_path, capsys):
    """main() creates a missing output directory and prints the export count."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "windows/credential_access/test_rule.yml", make_rule())
    output = tmp_path / "docs" / "rule_manifest.json"  # docs/ does not exist yet
    missing_map = tmp_path / "no_map.yml"  # explicit missing map: entries get []

    main(["--rules-dir", str(rules_dir), "--output", str(output), "--rule-map", str(missing_map)])

    assert output.exists()
    assert "Exported 1 production rules" in capsys.readouterr().out


# -- wazuh_rule_ids / ADTE join (Phase 5) -------------------------------------


def write_rule_map(tmp_path, entries) -> Path:
    """Write a minimal wazuh/rule_map.yml and return its path."""
    path = tmp_path / "rule_map.yml"
    path.write_text(yaml.safe_dump({"schema_version": "1.0", "rules": entries}), encoding="utf-8")
    return path


def test_entry_always_has_wazuh_rule_ids_key():
    """The field is present even with no map - empty means 'no Wazuh twin yet'."""
    entry = extract_rule_entry(make_rule(), Path("rules/windows/r.yml"), Path("rules"))
    assert entry["wazuh_rule_ids"] == []


def test_wazuh_rule_ids_joined_by_sigma_id():
    """A rule's Wazuh IDs come from the map, keyed on the Sigma id."""
    rule = make_rule(id="sigma-1")
    mapping = {"sigma-1": ["100100", "100101"]}

    entry = extract_rule_entry(rule, Path("rules/windows/r.yml"), Path("rules"), mapping)

    assert entry["wazuh_rule_ids"] == ["100100", "100101"]


def test_unmapped_rule_gets_empty_wazuh_ids():
    rule = make_rule(id="sigma-unmapped")
    entry = extract_rule_entry(rule, Path("rules/windows/r.yml"), Path("rules"), {"other": ["100100"]})
    assert entry["wazuh_rule_ids"] == []


def test_load_wazuh_rule_ids_reads_map_and_stringifies(tmp_path):
    """IDs are coerced to strings; suppression IDs are excluded from the join."""
    map_path = write_rule_map(tmp_path, [
        {"sigma_id": "s1", "wazuh_rule_ids": [100100], "wazuh_suppression_ids": [100111]},
    ])

    mapping = load_wazuh_rule_ids(map_path)

    assert mapping == {"s1": ["100100"]}  # ints -> strings, suppression excluded


def test_load_wazuh_rule_ids_missing_map_is_empty(tmp_path):
    assert load_wazuh_rule_ids(tmp_path / "nope.yml") == {}
    assert load_wazuh_rule_ids(None) == {}


def test_manifest_wazuh_ids_change_breaks_idempotence(tmp_path):
    """Changing a rule's Wazuh mapping must trigger a rewrite (content changed)."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "windows/r.yml", make_rule(id="s1"))
    output = tmp_path / "docs" / "manifest.json"

    write_manifest(build_manifest(rules_dir, {"s1": ["100100"]}), output)
    # Same rules, different Wazuh mapping -> not idempotent, must rewrite
    assert write_manifest(build_manifest(rules_dir, {"s1": ["100999"]}), output) is True
    with open(output, encoding="utf-8") as f:
        assert json.load(f)["rules"][0]["wazuh_rule_ids"] == ["100999"]
