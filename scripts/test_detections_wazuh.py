#!/usr/bin/env python3
"""
Tier-2 functional detection testing against a LIVE Wazuh manager.

Where Tier 1 (test_detections.py) evaluates converted SPL offline, this
runner feeds each sample's raw event payloads through the real Wazuh
analysis pipeline via the Manager API logtest endpoint and asserts on
which rule actually fired.

Assertion scoping (the critical design rule):
- True positive: PASSES if any of its events lands on one of the sample's
  expected_rule_ids (our custom rules, from wazuh/rule_map.yml).
- Benign: PASSES as long as NO event lands on any alerting ID in the rule
  map. Built-in Wazuh rules firing on benign events is normal; landing on
  a level-0 suppression child is the filter working - also a pass.
- We never assert "nothing fired".

Samples opt in with a "wazuh" block:
    "wazuh": {
      "events": ["<raw event string>", ...],
      "expected_rule_ids": ["100100"],        # required for true positives
      "log_format": "json",                    # optional, default json
      "location": "EventChannel"               # optional, default EventChannel
    }
Samples without the block are skipped with a visible note.

Exit codes: 0 all pass / 1 detection failure or FP / 2 infrastructure
failure (VM unreachable, auth) - so automation can tell "rules broken"
from "lab down". This runner NEVER restarts the manager.
"""

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from wazuh_client import WazuhClientError, WazuhConfig, WazuhManagerClient


REPO_ROOT = Path(__file__).resolve().parent.parent

EXIT_OK = 0
EXIT_DETECTION_FAILURE = 1
EXIT_INFRA_FAILURE = 2


@dataclass
class WazuhSample:
    """One sample's Tier-2 payloads and expectations."""

    name: str
    sample_type: str  # "true_positive" | "benign"
    events: list[str]
    expected_rule_ids: list[str]
    log_format: str = "json"
    location: str = "EventChannel"

    @classmethod
    def load(cls, filepath: Path) -> Optional["WazuhSample"]:
        """Return the sample, or None when it has no wazuh block (Tier-1 only)."""
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)

        wazuh = data.get("wazuh")
        if not isinstance(wazuh, dict) or not wazuh.get("events"):
            return None

        return cls(
            name=data.get("name", filepath.stem),
            sample_type=data.get("type", "unknown"),
            events=[str(e) for e in wazuh["events"]],
            expected_rule_ids=[str(r) for r in wazuh.get("expected_rule_ids", [])],
            log_format=wazuh.get("log_format", "json"),
            location=wazuh.get("location", "EventChannel"),
        )


@dataclass
class SampleResult:
    name: str
    sample_type: str
    passed: bool
    matched_rule_ids: list[str] = field(default_factory=list)
    expected_rule_ids: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def load_scoping(rule_map_path: Path) -> tuple[set[str], set[str]]:
    """Alerting-ID and suppression-ID sets from the rule map."""
    with open(rule_map_path, encoding="utf-8") as f:
        rule_map = yaml.safe_load(f)

    alerting: set[str] = set()
    suppression: set[str] = set()
    for entry in rule_map.get("rules", []):
        alerting.update(str(r) for r in entry.get("wazuh_rule_ids", []))
        suppression.update(str(r) for r in entry.get("wazuh_suppression_ids", []))
    return alerting, suppression


def load_wazuh_samples(samples_dir: Path) -> tuple[list[WazuhSample], list[str]]:
    """All Tier-2-capable samples, plus names of those skipped (no wazuh block)."""
    samples: list[WazuhSample] = []
    skipped: list[str] = []
    for subdir in ("true_positives", "benign"):
        directory = samples_dir / subdir
        if not directory.is_dir():
            continue
        for filepath in sorted(directory.glob("*.json")):
            sample = WazuhSample.load(filepath)
            if sample is None:
                skipped.append(filepath.stem)
            else:
                samples.append(sample)
    return samples, skipped


def evaluate_sample(
    sample: WazuhSample,
    fired_ids: list[str],
    alerting_ids: set[str],
    suppression_ids: set[str],
) -> SampleResult:
    """Apply the scoped pass/fail rules to the rule IDs logtest reported."""
    result = SampleResult(
        name=sample.name,
        sample_type=sample.sample_type,
        passed=True,
        matched_rule_ids=fired_ids,
        expected_rule_ids=sample.expected_rule_ids,
    )

    if sample.sample_type == "true_positive":
        if not sample.expected_rule_ids:
            result.passed = False
            result.notes.append("true positive sample has no expected_rule_ids")
        elif not any(rid in sample.expected_rule_ids for rid in fired_ids):
            result.passed = False
            result.notes.append(
                f"expected one of {sample.expected_rule_ids}, engine fired {fired_ids or ['nothing']}"
            )
    else:  # benign
        false_fires = [rid for rid in fired_ids if rid in alerting_ids]
        if false_fires:
            result.passed = False
            result.notes.append(f"FALSE POSITIVE: alerting rule(s) {false_fires} fired")
        suppressed = [rid for rid in fired_ids if rid in suppression_ids]
        if suppressed:
            result.notes.append(f"suppression child {suppressed} caught it - filter working")

    return result


def run_functional_tests(
    client: WazuhManagerClient,
    samples: list[WazuhSample],
    alerting_ids: set[str],
    suppression_ids: set[str],
) -> list[SampleResult]:
    """Send every sample event through logtest; one session, cleaned up after."""
    results = []
    try:
        for sample in samples:
            fired: list[str] = []
            for event in sample.events:
                outcome = client.logtest(event, sample.log_format, sample.location)
                if outcome.rule_id is not None:
                    fired.append(outcome.rule_id)
            results.append(evaluate_sample(sample, fired, alerting_ids, suppression_ids))
    finally:
        client.close_logtest_session()
    return results


def build_report(results: list[SampleResult], skipped: list[str]) -> dict:
    """Tier-1-shaped JSON with the additive tier marker."""
    false_positives = sum(
        1 for r in results if r.sample_type != "true_positive" and not r.passed
    )
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tier": "functional-wazuh",
        "summary": {
            "total_samples": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
            "total_false_positives": false_positives,
            "skipped_no_wazuh_block": skipped,
        },
        "results": {
            r.name: {
                "passed": r.passed,
                "type": r.sample_type,
                "matched_rule_ids": r.matched_rule_ids,
                "expected_rule_ids": r.expected_rule_ids,
                "notes": r.notes,
            }
            for r in results
        },
    }


def main(argv: Optional[list[str]] = None) -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(REPO_ROOT / ".env")
    except ImportError:
        pass

    parser = argparse.ArgumentParser(
        description="Functional detection tests against a live Wazuh manager"
    )
    parser.add_argument("--samples-dir", default=str(REPO_ROOT / "tests" / "samples"))
    parser.add_argument("--rule-map", default=str(REPO_ROOT / "wazuh" / "rule_map.yml"))
    parser.add_argument("--output", default="wazuh_results.json")
    parser.add_argument("--fail-on-fp", action="store_true",
                        help="Exit 1 if any benign sample fires an alerting rule")
    args = parser.parse_args(argv)

    alerting_ids, suppression_ids = load_scoping(Path(args.rule_map))
    samples, skipped = load_wazuh_samples(Path(args.samples_dir))

    print("=" * 60)
    print("TIER 2: FUNCTIONAL DETECTION TESTS (live Wazuh engine)")
    print("=" * 60)
    print(f"Samples with wazuh payloads: {len(samples)}")
    for name in skipped:
        print(f"⚠️  skipped (no wazuh block): {name}")

    if not samples:
        print("❌ Nothing to test - add wazuh blocks to tests/samples/*.json")
        sys.exit(EXIT_DETECTION_FAILURE)

    try:
        client = WazuhManagerClient(WazuhConfig.from_env())
        client.authenticate()  # fail fast into the infra exit code
        results = run_functional_tests(client, samples, alerting_ids, suppression_ids)
    except WazuhClientError as e:
        print(f"❌ Infrastructure failure: {e}")
        print("   Is the Wazuh VM up? Are rules deployed (deploy_wazuh_rules.py)?")
        sys.exit(EXIT_INFRA_FAILURE)

    report = build_report(results, skipped)
    with open(args.output, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=2)

    for r in results:
        marker = "✅" if r.passed else "❌"
        print(f"{marker} [{r.sample_type}] {r.name} -> fired {r.matched_rule_ids or 'nothing'}")
        for note in r.notes:
            print(f"     {note}")

    summary = report["summary"]
    print("=" * 60)
    print(f"Total: {summary['total_samples']}  Passed: {summary['passed']}  "
          f"Failed: {summary['failed']}  FPs: {summary['total_false_positives']}")
    print(f"Results written to: {args.output}")

    if summary["failed"] > 0:
        sys.exit(EXIT_DETECTION_FAILURE)
    if args.fail_on_fp and summary["total_false_positives"] > 0:
        sys.exit(EXIT_DETECTION_FAILURE)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    main()
