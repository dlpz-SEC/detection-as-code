#!/usr/bin/env python3
"""
Production Rule Manifest Exporter

Exports a machine-readable JSON manifest of all production-lifecycle rules
for downstream consumers - primarily ADTE (Autonomous Detection Triage
Engine), which maps triaged incidents back to detection coverage, confidence
weighting, and tuning guidance.

The write is idempotent: the manifest file is only rewritten when rule
content actually changes, so `generated_at` means "when the production rule
set last changed", not "when the exporter last ran". Downstream consumers
can treat it as a content-change watermark, and CI's commit-if-changed step
never produces timestamp-only commits.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml


# Manifest schema version - bump when the manifest structure changes
SCHEMA_VERSION = "1.0"

# Confidence weights (mirrors generate_coverage.py - scripts stay self-contained)
DEFAULT_CONFIDENCE_WEIGHT = 0.3
CONFIDENCE_WEIGHTS = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
}

# Technique tags look like t1003 / t1003.001 once the "attack." prefix is
# stripped; tactic tags (e.g. credential_access) don't match this pattern
TECHNIQUE_TAG_RE = re.compile(r"^t\d{4}(\.\d{3})?$")


def extract_technique_tags(tags: list) -> list[str]:
    """
    Extract MITRE ATT&CK technique IDs from a rule's tag list.

    `attack.t1003.001` -> `T1003.001`. Tactic tags and non-string entries
    are dropped; duplicates are removed preserving first-seen order.
    """
    # A rule with an empty `tags:` key yields None (not the []-default), and a
    # malformed tags value could be any type - never iterate a non-list
    if not isinstance(tags, list):
        return []

    techniques = []
    for tag in tags:
        if not isinstance(tag, str) or not tag.startswith("attack."):
            continue

        value = tag[7:]  # Remove "attack." prefix

        # Match case-insensitively so a non-standard `attack.T1003` is still
        # captured, but always emit the canonical uppercase form
        if TECHNIQUE_TAG_RE.match(value.lower()):
            techniques.append(value.upper())

    return list(dict.fromkeys(techniques))


def load_wazuh_rule_ids(rule_map_path: Optional[Path]) -> dict[str, list[str]]:
    """
    Map each Sigma rule id -> its alerting Wazuh rule IDs (wazuh/rule_map.yml).

    Optional: a missing or unreadable map yields an empty mapping, so every
    entry still gets `wazuh_rule_ids: []` - a visible "no Wazuh twin yet"
    signal rather than an absent field. Suppression children (level 0) never
    produce alerts, so they are excluded: the join key is the alert `rule.id`
    ADTE actually sees in wazuh-alerts-*.
    """
    if rule_map_path is None or not rule_map_path.is_file():
        return {}
    try:
        with open(rule_map_path, encoding="utf-8") as f:
            rule_map = yaml.safe_load(f)
    except (yaml.YAMLError, OSError) as e:
        print(f"⚠️  Warning: could not read rule map {rule_map_path}: {e}")
        return {}

    mapping: dict[str, list[str]] = {}
    for entry in (rule_map or {}).get("rules", []):
        sigma_id = entry.get("sigma_id")
        if sigma_id:
            mapping[sigma_id] = [str(r) for r in entry.get("wazuh_rule_ids", [])]
    return mapping


def extract_rule_entry(
    rule: object,
    rule_path: Path,
    rules_dir: Path,
    wazuh_ids_by_sigma: Optional[dict[str, list[str]]] = None,
) -> Optional[dict]:
    """
    Build a manifest entry for one rule, or None if it isn't production.

    Lifecycle and confidence are normalized (strip + lowercase) so casing
    variations in rule files don't silently drop rules from the manifest.
    """
    if not isinstance(rule, dict):
        return None

    custom = rule.get("custom")
    if not isinstance(custom, dict):
        return None

    lifecycle = custom.get("lifecycle")
    if isinstance(lifecycle, str):
        lifecycle = lifecycle.strip().lower()
    if lifecycle != "production":
        return None

    confidence = custom.get("confidence")
    if isinstance(confidence, str):
        confidence = confidence.strip().lower()

    false_positive_rate = custom.get("false_positive_rate")
    if isinstance(false_positive_rate, str):
        false_positive_rate = false_positive_rate.strip()

    # Block scalars carry a trailing newline - strip so the manifest is clean
    tuning_notes = custom.get("tuning_notes")
    if isinstance(tuning_notes, str):
        tuning_notes = tuning_notes.strip()

    # POSIX-style path anchored at the rules dir name so the manifest is
    # byte-identical regardless of OS or how --rules-dir was spelled
    path = (Path(rules_dir.name) / rule_path.relative_to(rules_dir)).as_posix()

    # Native Wazuh rule IDs for this detection (ADTE joins live alert rule.id
    # against this list). Empty when the rule has no Wazuh twin in rule_map.yml.
    wazuh_rule_ids = (wazuh_ids_by_sigma or {}).get(rule.get("id"), [])

    return {
        "id": rule.get("id"),
        "title": rule.get("title", "Unknown"),
        "path": path,
        "techniques": extract_technique_tags(rule.get("tags", [])),
        "lifecycle": lifecycle,
        "confidence": confidence,
        "confidence_weight": CONFIDENCE_WEIGHTS.get(confidence, DEFAULT_CONFIDENCE_WEIGHT),
        "false_positive_rate": false_positive_rate,
        "tuning_notes": tuning_notes,
        "wazuh_rule_ids": wazuh_rule_ids,
    }


def warn_on_id_issues(entries: list[dict]) -> None:
    """
    Warn (non-fatally) about missing or duplicate rule ids.

    ADTE joins triaged incidents back to detections on `id`, so a null or
    duplicated id silently breaks that mapping. Schema validation (CI stage 1)
    is the hard gate; this is a defense-in-depth heads-up at export time.
    """
    seen: dict[object, list[str]] = {}
    for entry in entries:
        rule_id = entry.get("id")
        if not rule_id:
            print(f"⚠️  Warning: rule has no id: {entry['path']}")
            continue
        seen.setdefault(rule_id, []).append(entry["path"])

    for rule_id, paths in seen.items():
        if len(paths) > 1:
            print(f"⚠️  Warning: duplicate rule id {rule_id}: {', '.join(paths)}")


def build_manifest(
    rules_dir: Path,
    wazuh_ids_by_sigma: Optional[dict[str, list[str]]] = None,
) -> dict:
    """Walk rules_dir and build the manifest dict of all production rules."""
    entries = []

    for rule_path in sorted(rules_dir.rglob("*.yml")):
        try:
            with open(rule_path, encoding="utf-8") as f:
                rule = yaml.safe_load(f)
        except (yaml.YAMLError, OSError) as e:
            print(f"⚠️  Warning: could not parse {rule_path}: {e}")
            continue

        entry = extract_rule_entry(rule, rule_path, rules_dir, wazuh_ids_by_sigma)
        if entry is not None:
            entries.append(entry)

    entries.sort(key=lambda e: e["path"])
    warn_on_id_issues(entries)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rule_count": len(entries),
        "rules": entries,
    }


def manifest_content(manifest: dict) -> dict:
    """The manifest minus its timestamp - the part that defines 'changed'."""
    return {k: v for k, v in manifest.items() if k != "generated_at"}


def write_manifest(manifest: dict, output_path: Path) -> bool:
    """
    Write the manifest, unless the existing file already has the same content.

    Returns True if the file was (re)written, False if left untouched.
    Comparison ignores `generated_at`, so an unchanged rule set preserves the
    previous file (and its timestamp) byte for byte.
    """
    # Serialize up front: a non-JSON-serializable value (e.g. a bare YAML date)
    # raises here, BEFORE we open the file, so we never leave a truncated
    # manifest behind - the last good file (which ADTE consumes) survives.
    payload = json.dumps(manifest, indent=2) + "\n"

    if output_path.exists():
        try:
            with open(output_path, encoding="utf-8") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, OSError):
            existing = None

        if isinstance(existing, dict) and manifest_content(existing) == manifest_content(manifest):
            return False

    output_path.parent.mkdir(parents=True, exist_ok=True)

    # newline="\n" keeps output LF-only on Windows so local runs and Linux CI
    # produce byte-identical files (a CRLF flip-flop would defeat idempotence)
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(payload)

    return True


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Export a JSON manifest of production rules for ADTE consumption"
    )
    parser.add_argument(
        "--rules-dir",
        default="rules",
        help="Directory containing Sigma rule YAML files (default: rules)"
    )
    parser.add_argument(
        "--output",
        default="docs/rule_manifest.json",
        help="Manifest output path (default: docs/rule_manifest.json)"
    )
    parser.add_argument(
        "--rule-map",
        default="wazuh/rule_map.yml",
        help="Wazuh rule map for wazuh_rule_ids (default: wazuh/rule_map.yml; "
             "optional - entries get an empty list if it's absent)"
    )
    args = parser.parse_args(argv)

    rules_dir = Path(args.rules_dir)
    if not rules_dir.is_dir():
        print(f"❌ Rules directory not found: {rules_dir}")
        sys.exit(1)

    wazuh_ids_by_sigma = load_wazuh_rule_ids(Path(args.rule_map))
    manifest = build_manifest(rules_dir, wazuh_ids_by_sigma)
    output_path = Path(args.output)
    changed = write_manifest(manifest, output_path)

    print("=" * 60)
    print("RULE MANIFEST EXPORT")
    print("=" * 60)
    if changed:
        print(f"✅ Exported {manifest['rule_count']} production rules to {output_path.as_posix()}")
    else:
        print(
            f"✅ Manifest unchanged ({manifest['rule_count']} production rules) - "
            f"{output_path.as_posix()} not modified"
        )


if __name__ == "__main__":
    # Windows consoles/pipes may default to cp1252, which can't encode the
    # emoji status markers - degrade them to '?' instead of crashing
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    main()
