#!/usr/bin/env python3
"""Make converted kusto predicates Event-table-aware for Microsoft Sentinel.

`sigma convert --target kusto --pipeline sysmon` emits BARE predicates over raw
Sysmon field names (Image, CommandLine, GrantedAccess, ...) with no table. The
Azure Monitor Agent lands Sysmon rows in the generic `Event` table with those
fields buried in the EventData XML (see infra/modules/dcr.bicep), so the bare
predicate matches nothing as-is. This wraps each Sysmon rule's predicate with the
`Sysmon` parser function (sentinel/parsers/Sysmon.kql), which re-materialises the
columns, producing a runnable query:

    Sysmon
    | where <predicate>

Driven by sentinel/rule_map.yml. Each rule's `target` decides the wrap:
  parser       -> `Sysmon | where <predicate>`   (Event table, parser-fronted)
  native       -> `<table> | where <predicate>`  (clean first-class columns)
  unsupported  -> skipped with a logged reason (Linux syslog, enrichment fields)
  none         -> no kusto output exists (correlation rules); skipped

Skips are LOGGED, never silent. Output mirrors the input directory structure
under --out-dir. Exit codes: 0 wrapped/skipped as expected, 1 a parser/native
target had a missing or empty predicate, 2 config/IO failure.
"""

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

WRAP_TARGETS = {"parser", "native"}
SKIP_TARGETS = {"unsupported", "none"}


def wrap_query(predicate: str, source: str, parser_name: str = "Sysmon") -> str:
    """Front a bare kusto predicate with its table/parser source.

    Pure and deterministic: strips the predicate, then emits
    `<source>\\n| where <predicate>\\n`. Raises ValueError on an empty predicate
    so a parser/native target can never silently produce a table-only query that
    matches every row.
    """
    pred = predicate.strip()
    if not pred:
        raise ValueError("empty predicate")
    return f"{source}\n| where {pred}\n"


@dataclass
class Result:
    wrapped: list[tuple[str, Path]] = field(default_factory=list)  # (sigma_path, out_file)
    skipped: list[tuple[str, str]] = field(default_factory=list)   # (sigma_path, reason)
    errors: list[str] = field(default_factory=list)


def load_rule_map(rule_map_path: Path) -> dict:
    with open(rule_map_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def build(
    rule_map: dict,
    kusto_dir: Path,
    out_dir: Path,
    parser_name: str = "Sysmon",
    write: bool = True,
) -> Result:
    """Wrap every parser/native rule, skip the rest with a reason. No exceptions
    escape for per-rule problems — they land in Result.errors so the caller can
    report them all at once and choose the exit code."""
    result = Result()

    for entry in rule_map.get("rules", []):
        sigma_path = entry.get("sigma_path", "<unknown>")
        target = entry.get("target")

        if target in SKIP_TARGETS:
            reason = " ".join((entry.get("reason") or target).split())
            result.skipped.append((sigma_path, reason))
            continue

        if target not in WRAP_TARGETS:
            result.errors.append(f"{sigma_path}: unknown target {target!r}")
            continue

        kusto_rel = entry.get("kusto")
        if not kusto_rel:
            result.errors.append(f"{sigma_path}: target {target!r} but no kusto path")
            continue

        # Resolve the predicate file relative to --kusto-dir when the map stores a
        # repo-root-relative path (output/kusto/...); otherwise treat it as given.
        kusto_path = Path(kusto_rel)
        if kusto_path.parts[:2] == ("output", "kusto"):
            kusto_path = kusto_dir / Path(*kusto_path.parts[2:])
        elif not kusto_path.is_absolute():
            kusto_path = kusto_dir / kusto_path

        if not kusto_path.is_file():
            result.errors.append(f"{sigma_path}: predicate file not found: {kusto_path}")
            continue

        source = parser_name if target == "parser" else entry.get("table")
        if not source:
            result.errors.append(f"{sigma_path}: target 'native' requires a `table` field")
            continue

        try:
            query = wrap_query(kusto_path.read_text(encoding="utf-8"), source, parser_name)
        except ValueError as e:
            result.errors.append(f"{sigma_path}: {e} in {kusto_path}")
            continue

        # Mirror the kusto tree under out_dir, keyed off the sigma path so the
        # layout matches rules/ (windows/execution/<name>.kql).
        rel = Path(sigma_path)
        rel = rel.relative_to("rules") if rel.parts[:1] == ("rules",) else rel
        out_file = out_dir / rel.with_suffix(".kql")

        if write:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(query, encoding="utf-8")
        result.wrapped.append((sigma_path, out_file))

    return result


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rule-map", default=str(REPO_ROOT / "sentinel" / "rule_map.yml"))
    parser.add_argument("--kusto-dir", default=str(REPO_ROOT / "output" / "kusto"))
    parser.add_argument("--out-dir", default=str(REPO_ROOT / "output" / "sentinel"))
    args = parser.parse_args(argv)

    try:
        rule_map = load_rule_map(Path(args.rule_map))
    except (OSError, yaml.YAMLError) as e:
        print(f"❌ cannot read rule map: {e}")
        return 2

    parser_name = (rule_map.get("parser") or {}).get("name", "Sysmon")
    result = build(rule_map, Path(args.kusto_dir), Path(args.out_dir), parser_name)

    print("=" * 60)
    print("SENTINEL QUERY GENERATION (Event-table-aware)")
    print("=" * 60)
    for sigma_path, out_file in result.wrapped:
        print(f"✅ wrapped: {sigma_path} -> {out_file}")
    for sigma_path, reason in result.skipped:
        print(f"⏭️  skip:    {sigma_path} — {reason}")
    for err in result.errors:
        print(f"❌ {err}")

    print("-" * 60)
    print(f"{len(result.wrapped)} wrapped, {len(result.skipped)} skipped, {len(result.errors)} error(s)")
    return 1 if result.errors else 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    sys.exit(main())
