#!/usr/bin/env python3
"""
Detection Behavioral Testing Framework

Tests converted SIEM queries against curated log samples to validate:
1. True Positive Detection: Rules trigger on malicious samples
2. False Positive Resistance: Rules don't trigger on benign samples

IMPORTANT LIMITATION:
This is a MOCK evaluator that parses Splunk SPL queries and evaluates
them against JSON log samples using Python pattern matching. It does NOT:
- Connect to actual Splunk
- Handle all SPL functions (transforming commands, stats, eval, subsearches)
- Provide production-grade query evaluation

What it DOES handle is the boolean search-expression subset that the Splunk
backend emits for these Sigma rules:
- ``field=value`` (case-insensitive, ``*`` wildcards)
- ``field IN ("v1", "v2", ...)`` (wildcards per value)
- ``NOT`` / ``AND`` (explicit or implicit by juxtaposition) / ``OR``
- Arbitrarily nested parentheses, including ``NOT (... OR ...)`` filter groups

That is enough to faithfully evaluate the real converted queries - the earlier
implementation flattened ``NOT (...)`` groups and treated wildcarded ``IN``
values as exact matches, so it could never match a true positive.

For production use, you would:
- Use Splunk's SDK for local query evaluation
- Connect to a Splunk dev instance via REST API
- Use tools like Atomic Red Team for live testing

This implementation demonstrates the TESTING METHODOLOGY, which is
the differentiator for a portfolio project.

Sample <-> rule association
---------------------------
A true-positive sample is only expected to fire the rule(s) for the technique
it demonstrates (``technique_id`` in the sample, ``attack.tXXXX`` tags on the
rule). Without this, every rule would be required to detect every sample - a
Mimikatz LSASS sample would "fail" the PowerShell rule. Benign samples are
tested against every rule: a benign event must fire nothing.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml


# Technique tags look like t1003 / t1003.001 once the "attack." prefix is
# stripped (tactic tags such as credential_access don't match). Kept local -
# by convention these pipeline scripts stay self-contained rather than
# importing from one another (see export_manifest.py / generate_coverage.py).
TECHNIQUE_TAG_RE = re.compile(r"^t\d{4}(\.\d{3})?$")

# Progress chatter sigma-cli writes to stderr. It should never reach a query
# file, but a conversion step that redirects 2>&1 would prepend it - strip it
# defensively so a stray banner can't poison the parse.
_SIGMA_NOISE_PREFIXES = ("Parsing Sigma rules",)


def extract_rule_techniques(tags: object) -> set[str]:
    """
    Extract MITRE ATT&CK technique IDs from a rule's tag list.

    ``attack.t1003.001`` -> ``T1003.001``. Tactic tags and non-string entries
    are ignored. Returns a set for O(1) membership checks during routing.
    """
    if not isinstance(tags, list):
        return set()

    techniques = set()
    for tag in tags:
        if not isinstance(tag, str) or not tag.startswith("attack."):
            continue
        value = tag[7:]  # strip "attack."
        if TECHNIQUE_TAG_RE.match(value.lower()):
            techniques.add(value.upper())
    return techniques


def technique_applies(sample_technique: Optional[str], rule_techniques: Optional[set[str]]) -> bool:
    """
    Decide whether a true-positive sample should be tested against a rule.

    - ``rule_techniques is None``: the rule's techniques couldn't be resolved
      (no sibling YAML) - fall back to testing the sample (never silently drop
      coverage because metadata was missing).
    - Sample has no ``technique_id``: it can't be routed to a specific rule;
      the caller warns and skips it so the gap is visible.
    - Otherwise match if the sample technique equals a rule technique, or one
      is a sub-technique of the other (T1003 <-> T1003.001).
    """
    if rule_techniques is None:
        return True
    if not sample_technique:
        return False

    st = sample_technique.strip().upper()
    for rt in rule_techniques:
        if st == rt or st.startswith(rt + ".") or rt.startswith(st + "."):
            return True
    return False


@dataclass
class TestSample:
    """A log sample for testing detections."""
    name: str
    filepath: str
    event_type: str  # "true_positive" or "benign"
    technique_id: Optional[str]  # For TP samples, which technique this demonstrates
    events: list[dict]

    @classmethod
    def load(cls, filepath: Path) -> "TestSample":
        """Load a test sample from a JSON file."""
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)

        return cls(
            name=data.get("name", filepath.stem),
            filepath=str(filepath),
            event_type=data.get("type", "unknown"),
            technique_id=data.get("technique_id"),
            events=data.get("events", [])
        )


# ---------------------------------------------------------------------------
# SPL evaluation: tokenizer -> recursive-descent parser -> AST evaluator
# ---------------------------------------------------------------------------

# AST nodes are plain tuples so the evaluator stays dependency-free:
#   ("and", [node, ...])
#   ("or", node, node)
#   ("not", node)
#   ("eq", field, value)          field = value  (value may hold * wildcards)
#   ("in", field, [value, ...])   field IN (v1, v2, ...)
#   ("kw", term)                  bare search term (full-text contains)

_KEYWORDS = {"AND", "OR", "NOT", "IN"}


def _tokenize(query: str) -> list[tuple[str, str]]:
    """Split an SPL search expression into (kind, value) tokens."""
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(query)
    while i < n:
        c = query[i]
        if c.isspace():
            i += 1
        elif c == "(":
            tokens.append(("LP", "(")); i += 1
        elif c == ")":
            tokens.append(("RP", ")")); i += 1
        elif c == ",":
            tokens.append(("COMMA", ",")); i += 1
        elif c == "=":
            tokens.append(("EQ", "=")); i += 1
        elif c == '"':
            # Quoted string; sigma escapes backslashes ("\\") and quotes ("\"").
            j = i + 1
            buf: list[str] = []
            while j < n and query[j] != '"':
                if query[j] == "\\" and j + 1 < n:
                    buf.append(query[j + 1])  # \\ -> \ , \" -> "
                    j += 2
                    continue
                buf.append(query[j])
                j += 1
            tokens.append(("STR", "".join(buf)))
            i = j + 1  # skip closing quote
        else:
            # Bareword: field name, unquoted value, or a keyword.
            j = i
            while j < n and query[j] not in ' \t\r\n(),="':
                j += 1
            tokens.append(("WORD", query[i:j]))
            i = j
    return tokens


class _Parser:
    """Recursive-descent parser for the SPL search-expression subset."""

    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.pos = 0

    def _peek(self) -> tuple[str, str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else ("EOF", "")

    def _advance(self) -> tuple[str, str]:
        tok = self._peek()
        self.pos += 1
        return tok

    def parse(self):
        if not self.tokens:
            return ("kw", "")  # empty query matches nothing (no event contains "")
        return self._parse_or()

    def _parse_or(self):
        node = self._parse_and()
        while True:
            kind, val = self._peek()
            if kind == "WORD" and val.upper() == "OR":
                self._advance()
                node = ("or", node, self._parse_and())
            else:
                return node

    def _parse_and(self):
        nodes = [self._parse_unary()]
        while True:
            kind, val = self._peek()
            if kind == "WORD" and val.upper() == "OR":
                break
            if kind in ("RP", "EOF"):
                break
            if kind == "WORD" and val.upper() == "AND":
                self._advance()  # explicit AND
                nodes.append(self._parse_unary())
                continue
            if kind in ("WORD", "LP"):  # implicit AND by juxtaposition
                nodes.append(self._parse_unary())
                continue
            # Anything else (stray STR/EQ/COMMA) isn't a new term at this level.
            self._advance()
        return nodes[0] if len(nodes) == 1 else ("and", nodes)

    def _parse_unary(self):
        kind, val = self._peek()
        if kind == "WORD" and val.upper() == "NOT":
            self._advance()
            return ("not", self._parse_unary())
        return self._parse_atom()

    def _parse_atom(self):
        kind, val = self._peek()
        if kind == "LP":
            self._advance()
            node = self._parse_or()
            if self._peek()[0] == "RP":
                self._advance()
            return node
        if kind == "WORD":
            field = self._advance()[1]
            nkind, nval = self._peek()
            if nkind == "WORD" and nval.upper() == "IN":
                self._advance()  # IN
                return ("in", field, self._parse_value_list())
            if nkind == "EQ":
                self._advance()  # =
                vkind, vval = self._peek()
                if vkind in ("STR", "WORD"):
                    self._advance()
                    return ("eq", field, vval)
                return ("eq", field, "")
            # Bare word -> full-text search term.
            return ("kw", field)
        # Unexpected token; consume and treat as a no-op true so it can't
        # silently negate a whole clause.
        self._advance()
        return ("true",)

    def _parse_value_list(self) -> list[str]:
        values: list[str] = []
        if self._peek()[0] == "LP":
            self._advance()
        while True:
            kind, val = self._peek()
            if kind in ("RP", "EOF"):
                if kind == "RP":
                    self._advance()
                break
            if kind == "COMMA":
                self._advance()
                continue
            if kind in ("STR", "WORD"):
                values.append(val)
                self._advance()
                continue
            self._advance()  # skip anything unexpected
        return values


def _value_match(pattern: str, value: object) -> bool:
    """Case-insensitive match of an SPL value against an event field value."""
    sval = str(value)
    if "*" in pattern or "?" in pattern:
        regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
        return re.fullmatch(regex, sval, re.IGNORECASE) is not None
    return sval.lower() == pattern.lower()


@dataclass
class QueryEvaluator:
    """
    Mock SPL query evaluator.

    Parses the Splunk search-expression subset the backend emits and evaluates
    the resulting boolean AST against JSON events.
    """

    def parse(self, query: str):
        """Parse an SPL search expression into an evaluation AST."""
        # Drop known sigma-cli progress banners and collapse to one line - the
        # backend emits these rules as a single-line search expression.
        lines = [
            ln for ln in query.splitlines()
            if ln.strip() and not any(ln.strip().startswith(p) for p in _SIGMA_NOISE_PREFIXES)
        ]
        cleaned = " ".join(lines).strip()

        # Strip a leading data-source selector (index=..., `macro`) if present;
        # it selects where to search, not which events match.
        cleaned = re.sub(r'^(index=\S+\s+|`[^`]+`\s+)', '', cleaned)

        return _Parser(_tokenize(cleaned)).parse()

    def _eval(self, node, event: dict) -> bool:
        op = node[0]
        if op == "and":
            return all(self._eval(child, event) for child in node[1])
        if op == "or":
            return self._eval(node[1], event) or self._eval(node[2], event)
        if op == "not":
            return not self._eval(node[1], event)
        if op == "eq":
            _, fieldname, value = node
            return fieldname in event and _value_match(value, event[fieldname])
        if op == "in":
            _, fieldname, values = node
            if fieldname not in event:
                return False
            return any(_value_match(v, event[fieldname]) for v in values)
        if op == "kw":
            term = node[1].lower()
            if not term:
                return False
            return any(term in str(v).lower() for v in event.values())
        if op == "true":
            return True
        return False

    def evaluate(self, query: str, events: list[dict]) -> list[dict]:
        """Evaluate a query against a list of events, returning the matches."""
        ast = self.parse(query)
        return [e for e in events if self._eval(ast, e)]


@dataclass
class TestResult:
    """Result of testing a single rule."""
    rule_name: str
    query_file: str
    passed: bool
    true_positives_detected: int
    true_positives_total: int
    false_positives: int
    benign_samples_tested: int
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def sensitivity(self) -> float:
        """Percentage of true positives detected."""
        if self.true_positives_total == 0:
            return 1.0
        return self.true_positives_detected / self.true_positives_total

    @property
    def specificity(self) -> float:
        """Percentage of benign samples correctly not flagged."""
        if self.benign_samples_tested == 0:
            return 1.0
        return (self.benign_samples_tested - self.false_positives) / self.benign_samples_tested


def load_test_samples(samples_dir: Path) -> tuple[list[TestSample], list[TestSample]]:
    """
    Load all test samples, separated by type.

    A sample with no ``events`` carries only a Tier-2 ``wazuh`` payload (raw
    log lines for the live-engine runner) and has nothing for this offline
    evaluator to match on, so it is skipped. This mirrors
    test_detections_wazuh.py skipping samples that have no ``wazuh`` block:
    each tier ignores what it cannot test.
    """
    true_positives = []
    benign = []

    tp_dir = samples_dir / "true_positives"
    benign_dir = samples_dir / "benign"

    if tp_dir.exists():
        for filepath in sorted(tp_dir.glob("*.json")):
            try:
                sample = TestSample.load(filepath)
                if not sample.events:
                    print(f"Skipping (Tier-2 only, no offline events): {filepath.stem}")
                    continue
                sample.event_type = "true_positive"
                true_positives.append(sample)
            except Exception as e:
                print(f"Warning: Could not load {filepath}: {e}")

    if benign_dir.exists():
        for filepath in sorted(benign_dir.glob("*.json")):
            try:
                sample = TestSample.load(filepath)
                if not sample.events:
                    print(f"Skipping (Tier-2 only, no offline events): {filepath.stem}")
                    continue
                sample.event_type = "benign"
                benign.append(sample)
            except Exception as e:
                print(f"Warning: Could not load {filepath}: {e}")

    return true_positives, benign


def resolve_rule_techniques(
    query_file: Path, queries_dir: Path, rules_dir: Optional[Path]
) -> Optional[set[str]]:
    """
    Find the technique tags of the Sigma rule that produced this query.

    The converted tree mirrors the rules tree, so
    ``output/splunk/windows/.../lsass_memory_access.txt`` maps back to
    ``rules/windows/.../lsass_memory_access.yml``. Returns None when the rule
    can't be resolved (no rules dir, or no sibling YAML), which the caller
    treats as "don't filter".
    """
    if rules_dir is None:
        return None
    try:
        rel = query_file.relative_to(queries_dir)
    except ValueError:
        return None

    rule_path = rules_dir / rel.with_suffix(".yml")
    if not rule_path.is_file():
        return None
    try:
        with open(rule_path, encoding="utf-8") as f:
            # safe_load_all: correlation rule files are multi-document; union
            # technique tags across every doc.
            docs = [d for d in yaml.safe_load_all(f) if isinstance(d, dict)]
    except (yaml.YAMLError, OSError):
        return None
    if not docs:
        return None
    techniques: set[str] = set()
    for doc in docs:
        techniques |= extract_rule_techniques(doc.get("tags", []))
    return techniques or None


def test_rule(
    query_file: Path,
    true_positive_samples: list[TestSample],
    benign_samples: list[TestSample],
    evaluator: QueryEvaluator,
    rule_techniques: Optional[set[str]] = None,
) -> TestResult:
    """Test a single converted rule against samples."""

    rule_name = query_file.stem
    errors = []
    notes = []

    # Load the converted query
    try:
        with open(query_file, encoding="utf-8") as f:
            query = f.read().strip()
    except Exception as e:
        return TestResult(
            rule_name=rule_name,
            query_file=str(query_file),
            passed=False,
            true_positives_detected=0,
            true_positives_total=0,
            false_positives=0,
            benign_samples_tested=0,
            errors=[f"Could not load query: {e}"]
        )

    # Test against true positives that target this rule's technique(s).
    tp_detected = 0
    tp_total = 0

    for sample in true_positive_samples:
        if not technique_applies(sample.technique_id, rule_techniques):
            # Sample is for a different technique - not this rule's job to
            # detect it. Only flag the case where we simply couldn't route it.
            if rule_techniques is not None and not sample.technique_id:
                notes.append(
                    f"Sample '{sample.name}' has no technique_id; skipped (cannot associate to a rule)"
                )
            continue

        tp_total += 1
        matches = evaluator.evaluate(query, sample.events)
        if matches:
            tp_detected += 1
        else:
            errors.append(f"Failed to detect true positive: {sample.name}")

    if tp_total == 0 and rule_techniques:
        notes.append(
            f"No true-positive sample covers technique(s) {sorted(rule_techniques)}; "
            "sensitivity is untested for this rule"
        )

    # Test against benign samples (any benign event firing any rule is an FP).
    fp_count = 0
    benign_tested = 0

    for sample in benign_samples:
        benign_tested += 1
        matches = evaluator.evaluate(query, sample.events)
        if matches:
            fp_count += 1
            errors.append(f"False positive on benign sample: {sample.name}")

    # Determine pass/fail
    # Rules pass if they:
    # - Detect at least 80% of true positives (if any apply to this rule)
    # - Have zero false positives
    sensitivity_threshold = 0.8
    passed = True

    if tp_total > 0 and (tp_detected / tp_total) < sensitivity_threshold:
        passed = False

    if fp_count > 0:
        passed = False

    return TestResult(
        rule_name=rule_name,
        query_file=str(query_file),
        passed=passed,
        true_positives_detected=tp_detected,
        true_positives_total=tp_total,
        false_positives=fp_count,
        benign_samples_tested=benign_tested,
        errors=errors,
        notes=notes,
    )


def main():
    parser = argparse.ArgumentParser(description="Test detections against log samples")
    parser.add_argument("--queries-dir", required=True, help="Directory with converted queries")
    parser.add_argument("--samples-dir", required=True, help="Directory with test samples")
    parser.add_argument("--output", required=True, help="Output JSON file")
    parser.add_argument(
        "--rules-dir",
        default="rules",
        help="Directory with the source Sigma rules, used to associate samples "
             "with rules by MITRE technique (default: rules). If it doesn't "
             "exist, every true-positive sample is tested against every rule.",
    )
    parser.add_argument("--fail-on-fp", action="store_true", help="Exit with error on false positives")
    args = parser.parse_args()

    queries_dir = Path(args.queries_dir)
    samples_dir = Path(args.samples_dir)
    rules_dir = Path(args.rules_dir)
    if not rules_dir.is_dir():
        print(f"Note: rules dir '{rules_dir}' not found - testing every sample against every rule")
        rules_dir = None

    # Load test samples
    true_positives, benign = load_test_samples(samples_dir)
    print(f"Loaded {len(true_positives)} true positive samples")
    print(f"Loaded {len(benign)} benign samples")

    # Initialize evaluator
    evaluator = QueryEvaluator()

    # Test all queries
    results: dict[str, dict] = {}
    total_passed = 0
    total_failed = 0
    total_fp = 0

    skipped_aggregation: list[str] = []

    for query_file in sorted(queries_dir.rglob("*.txt")):
        # The mock evaluator understands the boolean search-expression subset
        # only. Correlation rules convert to aggregation SPL (| stats ...),
        # which it cannot evaluate — skip those EXPLICITLY and say so, rather
        # than mis-evaluating the pipe tokens as keyword terms. Correlation
        # rules are validated by `sigma check` and covered upstream; they are
        # not behaviorally testable by this harness.
        query_text = query_file.read_text(encoding="utf-8")
        if re.search(r"\|\s*stats\b", query_text):
            skipped_aggregation.append(query_file.stem)
            print(f"Skipping: {query_file.stem}")
            print("  ⏭️  SKIPPED (aggregation query — correlation rules are "
                  "not evaluable by the boolean mock harness)")
            continue

        print(f"Testing: {query_file.stem}")

        rule_techniques = resolve_rule_techniques(query_file, queries_dir, rules_dir)
        result = test_rule(query_file, true_positives, benign, evaluator, rule_techniques)
        results[result.rule_name] = {
            "passed": result.passed,
            "sensitivity": result.sensitivity,
            "specificity": result.specificity,
            "true_positives": f"{result.true_positives_detected}/{result.true_positives_total}",
            "false_positives": result.false_positives,
            "errors": result.errors,
            "notes": result.notes,
        }

        if result.passed:
            total_passed += 1
            print(f"  ✅ PASSED (TP: {result.true_positives_detected}/{result.true_positives_total}, FP: {result.false_positives})")
        else:
            total_failed += 1
            print(f"  ❌ FAILED (TP: {result.true_positives_detected}/{result.true_positives_total}, FP: {result.false_positives})")
            for error in result.errors[:3]:  # Show first 3 errors
                print(f"     - {error}")

        for note in result.notes:
            print(f"     ℹ️  {note}")

        total_fp += result.false_positives

    # Write results
    output = {
        "timestamp": datetime.utcnow().isoformat(),
        "summary": {
            "total_rules": total_passed + total_failed,
            "passed": total_passed,
            "failed": total_failed,
            "total_false_positives": total_fp,
            "skipped_aggregation": skipped_aggregation
        },
        "results": results
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"\n{'='*50}")
    print(f"Test Summary")
    print(f"{'='*50}")
    print(f"Total: {total_passed + total_failed}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")
    print(f"False Positives: {total_fp}")
    if skipped_aggregation:
        print(f"Skipped (aggregation, not evaluable): {len(skipped_aggregation)} "
              f"— {', '.join(skipped_aggregation)}")
    print(f"\nResults written to: {args.output}")

    # Exit with error if requested and FPs found
    if args.fail_on_fp and total_fp > 0:
        print("\nFailing due to false positives (--fail-on-fp)")
        exit(1)

    if total_failed > 0:
        exit(1)


if __name__ == "__main__":
    # Windows consoles/pipes may default to cp1252, which can't encode the
    # emoji status markers - degrade them to '?' instead of crashing (mirrors
    # export_manifest.py). CI runs on UTF-8 Linux, so markers render there.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    main()
