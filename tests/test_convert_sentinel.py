"""
Drift + correctness check for the Sentinel conversion seam:
sentinel/rule_map.yml <-> rules/**/*.yml <-> sentinel/parsers/Sysmon.kql.

Runs offline in CI (Unit Tests stage). Two independent concerns:

  * Structural (real map): every rule is accounted for, every target is valid,
    every skip carries a reason, and the Sysmon parser projects every field the
    parser-fronted predicates reference. These need no conversion output.
  * Wrapping (synthetic fixture): build() turns a bare predicate into
    `Sysmon | where <predicate>` and skips unsupported/none with a reason. Driven
    by an in-tmp rule_map so it does NOT depend on output/kusto/** existing (the
    unit-test job runs before any `sigma convert`).
"""

import re
from pathlib import Path

import pytest
import yaml

import convert_sentinel as cs

REPO_ROOT = Path(__file__).resolve().parents[1]
RULE_MAP_PATH = REPO_ROOT / "sentinel" / "rule_map.yml"
PARSER_PATH = REPO_ROOT / "sentinel" / "parsers" / "Sysmon.kql"

VALID_TARGETS = cs.WRAP_TARGETS | cs.SKIP_TARGETS

# Columns the Event table exposes natively (no parser projection needed).
NATIVE_EVENT_COLUMNS = {"EventID", "Computer", "Source", "TimeGenerated", "EventLog"}

# field <op> ... — the field identifier that precedes a KQL comparison/string op.
FIELD_REF_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s+(?:==|=~|!=|<>|contains|startswith|endswith|has|in~|in)\b"
)
# LHS of a parser projection: `Name = extract(...)` or `Name = replace_string(...)`.
PARSER_COL_RE = re.compile(r"^\s*(\w+)\s*=\s*(?:extract|replace_string)\(", re.MULTILINE)


def load_rule_map() -> dict:
    with open(RULE_MAP_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def rule_map() -> dict:
    return load_rule_map()


@pytest.fixture(scope="module")
def parser_columns() -> set[str]:
    text = PARSER_PATH.read_text(encoding="utf-8")
    return set(PARSER_COL_RE.findall(text))


# --------------------------------------------------------------------------- #
# Structural checks against the real map / parser
# --------------------------------------------------------------------------- #

def test_map_schema_and_parser_block(rule_map):
    assert rule_map["schema_version"] == "1.0"
    assert rule_map["rules"], "rule_map.yml has no rules"
    parser = rule_map.get("parser") or {}
    assert parser.get("name"), "rule_map.yml has no parser.name"
    assert (REPO_ROOT / parser["file"]).is_file(), "parser.file does not exist on disk"


def test_every_rule_file_is_mapped(rule_map):
    """No rule under rules/ may be silently unaccounted for (post-merge guard)."""
    mapped = {e["sigma_path"] for e in rule_map["rules"]}
    for sigma_path in (REPO_ROOT / "rules").rglob("*.yml"):
        rel = sigma_path.relative_to(REPO_ROOT).as_posix()
        assert rel in mapped, f"{rel} exists under rules/ but is not in sentinel/rule_map.yml"


def test_sigma_paths_exist(rule_map):
    for entry in rule_map["rules"]:
        assert (REPO_ROOT / entry["sigma_path"]).is_file(), f"missing: {entry['sigma_path']}"


def test_targets_are_valid(rule_map):
    for entry in rule_map["rules"]:
        assert entry.get("target") in VALID_TARGETS, (
            f"{entry['sigma_path']}: invalid target {entry.get('target')!r}"
        )


def test_skip_targets_have_reason(rule_map):
    for entry in rule_map["rules"]:
        if entry["target"] in cs.SKIP_TARGETS:
            assert (entry.get("reason") or "").strip(), (
                f"{entry['sigma_path']}: {entry['target']} target needs a reason"
            )


def test_wrap_targets_have_predicate_path(rule_map):
    for entry in rule_map["rules"]:
        if entry["target"] in cs.WRAP_TARGETS:
            assert entry.get("kusto"), f"{entry['sigma_path']}: {entry['target']} needs a kusto path"
        if entry["target"] == "none":
            assert entry.get("kusto") is None, f"{entry['sigma_path']}: 'none' must have kusto: null"


def test_sigma_ids_are_real(rule_map):
    """Every mapped sigma_id is an id that actually appears in its rule file."""
    for entry in rule_map["rules"]:
        with open(REPO_ROOT / entry["sigma_path"], encoding="utf-8") as f:
            ids = [d.get("id") for d in yaml.safe_load_all(f) if isinstance(d, dict)]
        assert entry["sigma_id"] in ids, (
            f"{entry['sigma_path']}: map sigma_id {entry['sigma_id']} not among {ids}"
        )


def test_parser_covers_referenced_fields(rule_map, parser_columns):
    """Each parser-fronted predicate must only reference fields the parser projects.

    Guards the silent-zero-rows failure: a Sysmon rule adding a field the parser
    doesn't materialise would match nothing. Skips a rule whose converted predicate
    isn't present (the unit-test job runs before `sigma convert`)."""
    available = parser_columns | NATIVE_EVENT_COLUMNS
    checked = 0
    for entry in rule_map["rules"]:
        if entry["target"] != "parser":
            continue
        pred_path = REPO_ROOT / entry["kusto"]
        if not pred_path.is_file():
            continue
        predicate = pred_path.read_text(encoding="utf-8")
        referenced = {m for m in FIELD_REF_RE.findall(predicate) if m[0].isupper()}
        missing = referenced - available
        assert not missing, (
            f"{entry['sigma_path']}: predicate references {sorted(missing)} "
            f"which Sysmon.kql does not project"
        )
        checked += 1
    if checked == 0:
        pytest.skip("no converted parser predicates present (run sigma convert first)")


# --------------------------------------------------------------------------- #
# wrap_query — pure
# --------------------------------------------------------------------------- #

def test_wrap_query_fronts_with_source():
    assert cs.wrap_query("EventID == 1 and X", "Sysmon") == "Sysmon\n| where EventID == 1 and X\n"


def test_wrap_query_strips_predicate():
    assert cs.wrap_query("  A == 1 \n\n", "Sysmon") == "Sysmon\n| where A == 1\n"


def test_wrap_query_rejects_empty():
    for empty in ("", "   ", "\n\n"):
        with pytest.raises(ValueError):
            cs.wrap_query(empty, "Sysmon")


# --------------------------------------------------------------------------- #
# build — synthetic fixture, no dependency on output/kusto
# --------------------------------------------------------------------------- #

def _synthetic_map(kusto_dir: Path) -> dict:
    (kusto_dir / "windows" / "execution").mkdir(parents=True, exist_ok=True)
    pred = kusto_dir / "windows" / "execution" / "powershell_encoded_command.txt"
    pred.write_text('EventID == 1 and Image endswith "\\\\powershell.exe"\n', encoding="utf-8")
    return {
        "schema_version": "1.0",
        "parser": {"name": "Sysmon", "file": "sentinel/parsers/Sysmon.kql"},
        "rules": [
            {
                "sigma_id": "a5c8d2e1-3f4b-5a6c-7d8e-9f0a1b2c3d4e",
                "sigma_path": "rules/windows/execution/powershell_encoded_command.yml",
                "kusto": "output/kusto/windows/execution/powershell_encoded_command.txt",
                "target": "parser",
            },
            {
                "sigma_id": "0471bd9a-9b43-4f31-860f-4f8bf4950058",
                "sigma_path": "rules/linux/credential_access/ssh_brute_force.yml",
                "kusto": "output/kusto/linux/credential_access/ssh_brute_force.txt",
                "target": "unsupported",
                "reason": "Linux syslog; not collected by the DCR",
            },
            {
                "sigma_id": "2a9c4e6f-1b3d-4f8a-9c2e-6d5b7a0f1c3e",
                "sigma_path": "rules/windows/credential_access/bruteforce_failures_then_success.yml",
                "kusto": None,
                "target": "none",
                "reason": "correlation rule; no kusto output",
            },
        ],
    }


def test_build_wraps_parser_and_skips_rest(tmp_path):
    kusto_dir = tmp_path / "kusto"
    out_dir = tmp_path / "sentinel"
    rmap = _synthetic_map(kusto_dir)

    result = cs.build(rmap, kusto_dir, out_dir)

    assert not result.errors, result.errors
    assert len(result.wrapped) == 1
    assert len(result.skipped) == 2

    sigma_path, out_file = result.wrapped[0]
    assert out_file == out_dir / "windows" / "execution" / "powershell_encoded_command.kql"
    text = out_file.read_text(encoding="utf-8")
    assert text == 'Sysmon\n| where EventID == 1 and Image endswith "\\\\powershell.exe"\n'
    # skips carry their reason
    reasons = {sp: r for sp, r in result.skipped}
    assert "syslog" in reasons["rules/linux/credential_access/ssh_brute_force.yml"]


def test_build_errors_on_missing_predicate(tmp_path):
    """A parser target whose predicate file is absent is an error, not a silent skip."""
    kusto_dir = tmp_path / "kusto"
    kusto_dir.mkdir()
    rmap = {
        "schema_version": "1.0",
        "parser": {"name": "Sysmon"},
        "rules": [{
            "sigma_id": "x",
            "sigma_path": "rules/windows/execution/powershell_encoded_command.yml",
            "kusto": "output/kusto/windows/execution/powershell_encoded_command.txt",
            "target": "parser",
        }],
    }
    result = cs.build(rmap, kusto_dir, tmp_path / "out")
    assert result.errors and not result.wrapped


def test_build_native_requires_table(tmp_path):
    kusto_dir = tmp_path / "kusto"
    (kusto_dir / "windows" / "credential_access").mkdir(parents=True)
    (kusto_dir / "windows" / "credential_access" / "x.txt").write_text("A == 1\n", encoding="utf-8")
    rmap = {
        "schema_version": "1.0",
        "parser": {"name": "Sysmon"},
        "rules": [{
            "sigma_id": "x",
            "sigma_path": "rules/windows/credential_access/x.yml",
            "kusto": "output/kusto/windows/credential_access/x.txt",
            "target": "native",  # no `table` -> error
        }],
    }
    result = cs.build(rmap, kusto_dir, tmp_path / "out")
    assert result.errors and not result.wrapped
