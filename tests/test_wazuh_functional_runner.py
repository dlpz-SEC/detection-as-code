"""
Tests for scripts/test_detections_wazuh.py - all offline.

The Wazuh client is a MagicMock scripted with LogtestResults, so these
tests pin the runner's assertion scoping (the design's critical rule),
sample loading, report shape, and session cleanup without any network.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from test_detections_wazuh import (
    WazuhSample,
    build_report,
    evaluate_sample,
    load_scoping,
    load_wazuh_samples,
    run_functional_tests,
)
from wazuh_client import LogtestResult


ALERTING = {"100100", "100110"}
SUPPRESSION = {"100111"}


def make_sample(**overrides) -> WazuhSample:
    kwargs = {
        "name": "test-sample",
        "sample_type": "true_positive",
        "events": ['{"win": {}}'],
        "expected_rule_ids": ["100100"],
    }
    kwargs.update(overrides)
    return WazuhSample(**kwargs)


def logtest_result(rule_id, level=12) -> LogtestResult:
    return LogtestResult(
        rule_id=rule_id, level=level, description="x", decoder="json",
        alert=rule_id is not None, raw={},
    )


# -- assertion scoping (the critical design rule) -----------------------------


def test_true_positive_passes_on_expected_id():
    result = evaluate_sample(make_sample(), ["100100"], ALERTING, SUPPRESSION)
    assert result.passed


def test_true_positive_fails_when_only_builtin_fires():
    """A built-in (61612) firing is NOT detection - our rule must win."""
    result = evaluate_sample(make_sample(), ["61612"], ALERTING, SUPPRESSION)
    assert not result.passed
    assert "expected one of" in result.notes[0]


def test_true_positive_fails_on_no_fire():
    result = evaluate_sample(make_sample(), [], ALERTING, SUPPRESSION)
    assert not result.passed


def test_true_positive_without_expectations_fails_loudly():
    sample = make_sample(expected_rule_ids=[])
    result = evaluate_sample(sample, ["100100"], ALERTING, SUPPRESSION)
    assert not result.passed
    assert "no expected_rule_ids" in result.notes[0]


def test_benign_passes_when_builtin_fires():
    """Built-ins firing on benign events is normal - never a failure."""
    sample = make_sample(sample_type="benign", expected_rule_ids=[])
    result = evaluate_sample(sample, ["61612"], ALERTING, SUPPRESSION)
    assert result.passed


def test_benign_fails_when_our_alerting_rule_fires():
    sample = make_sample(sample_type="benign", expected_rule_ids=[])
    result = evaluate_sample(sample, ["100100"], ALERTING, SUPPRESSION)
    assert not result.passed
    assert "FALSE POSITIVE" in result.notes[0]


def test_benign_suppression_child_is_a_pass_with_note():
    """Landing on the level-0 child means the filter worked."""
    sample = make_sample(sample_type="benign", expected_rule_ids=[])
    result = evaluate_sample(sample, ["100111"], ALERTING, SUPPRESSION)
    assert result.passed
    assert any("filter working" in n for n in result.notes)


# -- sample loading ------------------------------------------------------------


def write_sample(directory: Path, name: str, payload: dict) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.json").write_text(json.dumps(payload), encoding="utf-8")


def test_load_skips_samples_without_wazuh_block(tmp_path):
    write_sample(tmp_path / "true_positives", "tier1_only",
                 {"name": "tier1_only", "type": "true_positive", "events": [{"EventID": 1}]})
    write_sample(tmp_path / "true_positives", "tier2",
                 {"name": "tier2", "type": "true_positive",
                  "wazuh": {"events": ["{}"], "expected_rule_ids": ["100100"]}})

    samples, skipped = load_wazuh_samples(tmp_path)

    assert [s.name for s in samples] == ["tier2"]
    assert skipped == ["tier1_only"]


def test_load_applies_format_defaults_and_string_coercion(tmp_path):
    write_sample(tmp_path / "benign", "b",
                 {"name": "b", "type": "benign", "wazuh": {"events": ["{}"], "expected_rule_ids": [100111]}})

    samples, _ = load_wazuh_samples(tmp_path)

    assert samples[0].log_format == "json"
    assert samples[0].location == "EventChannel"
    assert samples[0].expected_rule_ids == ["100111"]  # ints coerced to strings


def test_load_scoping_reads_rule_map(tmp_path):
    (tmp_path / "rule_map.yml").write_text(
        "rules:\n"
        "  - wazuh_rule_ids: ['100100']\n"
        "    wazuh_suppression_ids: []\n"
        "  - wazuh_rule_ids: ['100110']\n"
        "    wazuh_suppression_ids: ['100111']\n",
        encoding="utf-8",
    )

    alerting, suppression = load_scoping(tmp_path / "rule_map.yml")

    assert alerting == ALERTING
    assert suppression == SUPPRESSION


# -- runner + report -----------------------------------------------------------


def test_runner_sends_each_event_and_closes_session():
    client = MagicMock()
    client.logtest.side_effect = [logtest_result("100100"), logtest_result("61612")]
    samples = [
        make_sample(name="tp"),
        make_sample(name="benign", sample_type="benign", expected_rule_ids=[]),
    ]

    results = run_functional_tests(client, samples, ALERTING, SUPPRESSION)

    assert [r.passed for r in results] == [True, True]
    assert client.logtest.call_count == 2
    client.logtest.assert_any_call('{"win": {}}', "json", "EventChannel")
    client.close_logtest_session.assert_called_once()


def test_runner_closes_session_even_on_error():
    client = MagicMock()
    client.logtest.side_effect = RuntimeError("boom")

    with pytest.raises(RuntimeError):
        run_functional_tests(client, [make_sample()], ALERTING, SUPPRESSION)

    client.close_logtest_session.assert_called_once()


def test_report_shape_is_tier1_compatible_with_tier_marker():
    results = [
        evaluate_sample(make_sample(name="tp"), ["100100"], ALERTING, SUPPRESSION),
        evaluate_sample(
            make_sample(name="fp", sample_type="benign", expected_rule_ids=[]),
            ["100110"], ALERTING, SUPPRESSION,
        ),
    ]

    report = build_report(results, skipped=["tier1_only"])

    assert report["tier"] == "functional-wazuh"
    assert report["summary"]["total_samples"] == 2
    assert report["summary"]["passed"] == 1
    assert report["summary"]["failed"] == 1
    assert report["summary"]["total_false_positives"] == 1
    assert report["summary"]["skipped_no_wazuh_block"] == ["tier1_only"]
    assert report["results"]["fp"]["passed"] is False
    assert report["results"]["tp"]["matched_rule_ids"] == ["100100"]
