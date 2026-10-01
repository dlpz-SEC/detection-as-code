"""
Tests for scripts/generate_coverage.py

Covers the behavioral test-state mapping (a rule with no behavioral evidence
must never score as "passed"), technique-to-tactic resolution, tactic tag
forms, rule-file counting, technique names, and the report it writes.
"""

import json
import sys

import pytest
import yaml

from generate_coverage import (
    RuleCoverage,
    build_coverage_map,
    count_rule_files,
    generate_markdown_report,
    main,
    resolve_tactics,
    resolve_test_state,
)


def make_rule(tags, lifecycle="production", confidence="high", title="Test Rule"):
    return {
        "title": title,
        "level": "high",
        "tags": tags,
        "detection": {"selection": {"EventID": 1}, "condition": "selection"},
        "custom": {"lifecycle": lifecycle, "confidence": confidence},
    }


def write_rule(rules_dir, relpath, rule):
    path = rules_dir / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(rule, sort_keys=False), encoding="utf-8")
    return path


def results_for(**entries):
    """A test-results document in test_detections.py's output shape."""
    return {"summary": {"skipped_aggregation": []}, "results": entries}


# -- resolve_test_state -------------------------------------------------------

def test_no_test_results_is_untested():
    assert resolve_test_state("r", None) == ("untested", "no test results supplied")


def test_aggregation_skip_is_untested():
    results = {"summary": {"skipped_aggregation": ["r"]}, "results": {}}
    assert resolve_test_state("r", results) == ("untested", "aggregation query")


def test_rule_missing_from_results_is_untested():
    assert resolve_test_state("r", results_for()) == ("untested", "no Tier-1 result")


def test_zero_of_zero_pass_is_untested_not_passed():
    """The regression this file exists for: a 0/0 pass is a gate, not evidence."""
    results = results_for(r={"passed": True, "true_positives": "0/0", "sensitivity_tested": False})
    assert resolve_test_state("r", results) == ("untested", "no true-positive sample")


def test_exercised_pass_is_passed():
    results = results_for(r={"passed": True, "true_positives": "1/1", "sensitivity_tested": True})
    assert resolve_test_state("r", results) == ("passed", None)


def test_failure_is_failed_even_with_no_true_positives():
    """A false positive fails a rule whether or not any TP sample applied."""
    results = results_for(r={"passed": False, "true_positives": "0/0", "sensitivity_tested": False})
    assert resolve_test_state("r", results) == ("failed", None)


@pytest.mark.parametrize("tp, expected", [
    ("0/0", ("untested", "no true-positive sample")),
    ("2/2", ("passed", None)),
    ("not-a-ratio", ("untested", "no true-positive sample")),
])
def test_legacy_results_without_flag_fall_back_to_ratio(tp, expected):
    results = results_for(r={"passed": True, "true_positives": tp})
    assert resolve_test_state("r", results) == expected


def test_untested_production_high_rule_scores_point_six():
    rule = RuleCoverage(
        filepath="x.yml", title="x", techniques=["T1110"], tactics=[],
        lifecycle="production", confidence="high", level="medium",
        test_state="untested", untested_reason="no true-positive sample",
    )
    assert rule.coverage_score == pytest.approx(0.6)


# -- tactics ------------------------------------------------------------------

def test_resolve_tactics_keeps_only_tactics_mitre_assigns():
    rule_tactics = {"execution", "stealth"}
    assert resolve_tactics("T1027", rule_tactics) == ["stealth"]
    assert resolve_tactics("T1059.001", rule_tactics) == ["execution"]


def test_resolve_tactics_returns_matrix_order():
    assert resolve_tactics("T1078.002", {"persistence", "initial_access"}) == [
        "initial_access", "persistence",
    ]


def test_resolve_tactics_falls_back_to_mitre_when_rules_claim_none():
    assert resolve_tactics("T1003", {"execution"}) == ["credential_access"]


def test_resolve_tactics_unknown_technique_uses_rule_tactics():
    assert resolve_tactics("T9999", {"impact", "discovery"}) == ["discovery", "impact"]


def test_multi_technique_rule_does_not_smear_tactics(tmp_path):
    """T1027 must not appear under Execution, nor T1059 under Stealth."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "windows/execution/ps.yml", make_rule([
        "attack.execution", "attack.t1059", "attack.t1059.001",
        "attack.stealth", "attack.t1027",
    ]))
    cmap = build_coverage_map(rules_dir, None)
    assert cmap["T1027"].tactics == ["stealth"]
    assert cmap["T1059"].tactics == ["execution"]
    assert cmap["T1059.001"].tactics == ["execution"]


@pytest.mark.parametrize("legacy_tag", ["attack.defense-evasion", "attack.defense_evasion"])
def test_retired_defense_evasion_tag_counts_as_stealth(tmp_path, legacy_tag):
    """ATT&CK v19 renamed TA0005 to Stealth; a rule tagged the old way keeps its tactic."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "a/r.yml", make_rule([legacy_tag, "attack.t1027"]))
    assert build_coverage_map(rules_dir, None)["T1027"].tactics == ["stealth"]


def test_hyphen_and_underscore_tactic_tags_are_equivalent(tmp_path):
    hyphen, underscore = tmp_path / "h", tmp_path / "u"
    write_rule(hyphen, "a/r.yml", make_rule(["attack.credential-access", "attack.t1003"]))
    write_rule(underscore, "a/r.yml", make_rule(["attack.credential_access", "attack.t1003"]))
    h, u = build_coverage_map(hyphen, None), build_coverage_map(underscore, None)
    assert h["T1003"].tactics == u["T1003"].tactics == ["credential_access"]
    assert h["T1003"].coverage_score == u["T1003"].coverage_score


# -- counting, names, report ----------------------------------------------------

def test_rule_files_are_counted_once_not_per_technique(tmp_path):
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "a/one.yml", make_rule(
        ["attack.credential-access", "attack.t1110", "attack.t1110.001", "attack.t1110.003"]))
    write_rule(rules_dir, "a/two.yml", make_rule(["attack.credential-access", "attack.t1003"]))
    cmap = build_coverage_map(rules_dir, None)
    assert sum(len(t.rules) for t in cmap.values()) == 4  # rule-technique pairs
    assert count_rule_files(cmap) == 2


@pytest.mark.parametrize("tech_id, name", [
    ("T1078", "Valid Accounts"),
    ("T1078.002", "Domain Accounts"),
    ("T1110", "Brute Force"),
    ("T1110.001", "Password Guessing"),
    ("T1110.003", "Password Spraying"),
])
def test_repo_techniques_have_names(tmp_path, tech_id, name):
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "a/r.yml", make_rule(["attack.credential-access", f"attack.{tech_id.lower()}"]))
    assert build_coverage_map(rules_dir, None)[tech_id].technique_name == name


def test_report_names_each_untested_reason(tmp_path):
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "a/agg.yml", make_rule(["attack.credential-access", "attack.t1110"]))
    write_rule(rules_dir, "a/nosample.yml", make_rule(["attack.credential-access", "attack.t1110"]))
    results = {
        "summary": {"skipped_aggregation": ["agg"]},
        "results": {"nosample": {"passed": True, "true_positives": "0/0", "sensitivity_tested": False}},
    }
    report = generate_markdown_report(build_coverage_map(rules_dir, results))
    assert "| T1110 | Not behaviorally tested (aggregation query; no true-positive sample) |" in report
    assert "| Rule files | 2 |" in report
    assert "Tier-1 behavioral test results: included." in report


def test_report_says_when_test_results_were_not_supplied(tmp_path):
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "a/r.yml", make_rule(["attack.credential-access", "attack.t1003"]))
    report = generate_markdown_report(build_coverage_map(rules_dir, None), test_results_supplied=False)
    assert "not supplied, so every rule is scored as untested" in report
    assert "no test results supplied" in report


def test_main_writes_utf8_report(tmp_path, monkeypatch):
    """The report carries emoji; writing it must not depend on the OS code page."""
    rules_dir = tmp_path / "rules"
    write_rule(rules_dir, "a/r.yml", make_rule(["attack.credential-access", "attack.t1003"]))
    results_path = tmp_path / "test-results.json"
    results_path.write_text(json.dumps(results_for(
        r={"passed": True, "true_positives": "1/1", "sensitivity_tested": True})), encoding="utf-8")
    out = tmp_path / "COVERAGE.md"
    monkeypatch.setattr(sys, "argv", [
        "generate_coverage.py", "--rules-dir", str(rules_dir),
        "--test-results", str(results_path), "--output", str(out),
    ])
    main()
    text = out.read_text(encoding="utf-8")
    assert "\U0001f7e2 high" in text  # green circle: one passed, high-confidence rule
    assert "| Rule files | 1 |" in text
