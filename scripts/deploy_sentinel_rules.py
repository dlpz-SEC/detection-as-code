#!/usr/bin/env python3
"""
Deploy Detection-as-Code artifacts to a Microsoft Sentinel workspace.

Reads sentinel/rule_map.yml and the parser-fronted queries under output/sentinel/**
(produced by convert_sentinel.py), then, via the ARM REST API:

  1. Deploys the `Sysmon` parser as a workspace function (savedSearches), and
  2. Deploys each parser/native-target rule as a scheduled analytics rule,

verifying each artifact's query by readback before trusting it — the same
upload-then-verify discipline deploy_wazuh_rules.py uses for the Wazuh manager.
The parser goes first: a rule that invokes `Sysmon` before the function exists
would fail validation.

STATUS: built, live-UNVERIFIED. No workspace has been reachable this session
(no `az login`). This runs at Phase 4, after Phase 3 confirms the data path and
the parser against real rows. Deploying an *enabled* analytics rule starts it
evaluating on schedule — treat as a live change, not a smoke test.

Exit codes: 0 deployed/verified, 1 verification mismatch, 2 infra/config failure.
"""

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from sentinel_client import SentinelClient, SentinelClientError, SentinelConfig

REPO_ROOT = Path(__file__).resolve().parent.parent

PARSER_SAVED_SEARCH_ID = "dac-parser-sysmon"
PARSER_CATEGORY = "Detection-as-Code"

# Sigma level -> Sentinel severity (Sentinel has no Critical; it tops out at High).
_SEVERITY = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}

# Sigma tactic tag -> Sentinel `tactics` enum value (PascalCase, no separators).
_TACTIC = {
    "initial_access": "InitialAccess",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "PrivilegeEscalation",
    "defense_evasion": "DefenseEvasion",
    "credential_access": "CredentialAccess",
    "discovery": "Discovery",
    "lateral_movement": "LateralMovement",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
    "command_and_control": "CommandAndControl",
    "impact": "Impact",
}

_TECHNIQUE_TAG_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)


def _normalise(text: str) -> str:
    """Line-ending-insensitive compare for readback verification."""
    return text.replace("\r\n", "\n").strip()


# -- pure body builders (unit-tested offline) --------------------------------

def severity_from_level(level: Optional[str]) -> str:
    return _SEVERITY.get((level or "medium").strip().lower(), "Medium")


def tactics_from_tags(tags: list) -> list[str]:
    """Sentinel tactics from a Sigma rule's `attack.<tactic>` tags (technique
    tags excluded). Deterministic order preserves the rule's declared sequence."""
    tactics: list[str] = []
    for tag in tags or []:
        tag = str(tag)
        if not tag.startswith("attack.") or _TECHNIQUE_TAG_RE.match(tag):
            continue
        mapped = _TACTIC.get(tag[len("attack."):])
        if mapped and mapped not in tactics:
            tactics.append(mapped)
    return tactics


def parent_techniques(techniques: list) -> list[str]:
    """Parent technique IDs only (strip sub-technique suffix), deduped + sorted.
    Sentinel's `techniques` field takes parent IDs; sub-techniques carry in the
    Sigma tags and rule description."""
    parents = {str(t).split(".")[0].upper() for t in (techniques or [])}
    return sorted(parents)


def build_function_body(name: str, query: str, category: str = PARSER_CATEGORY) -> dict:
    return {
        "properties": {
            "category": category,
            "displayName": name,
            "functionAlias": name,
            "query": query.strip(),
            "version": 2,
            "functionParameters": "",
        }
    }


def build_alert_rule_body(sigma_rule: dict, query: str, techniques: list) -> dict:
    desc = (sigma_rule.get("description") or "").strip()
    return {
        "kind": "Scheduled",
        "properties": {
            "displayName": sigma_rule.get("title") or "Detection-as-Code rule",
            "description": desc[:5000],
            "severity": severity_from_level(sigma_rule.get("level")),
            "enabled": True,
            "query": query.strip(),
            "queryFrequency": "PT1H",
            "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "tactics": tactics_from_tags(sigma_rule.get("tags", [])),
            "techniques": parent_techniques(techniques),
        },
    }


# -- deployable assembly ------------------------------------------------------

@dataclass
class Artifact:
    """One thing to PUT: (kind, id, body, query-for-verify, label)."""
    kind: str          # "function" | "rule"
    id: str
    body: dict
    query: str
    label: str


def _load_sigma_doc(sigma_path: Path, sigma_id: str) -> dict:
    """Return the doc in a (possibly multi-doc) Sigma file whose id matches."""
    with open(sigma_path, encoding="utf-8") as f:
        docs = [d for d in yaml.safe_load_all(f) if isinstance(d, dict)]
    for d in docs:
        if d.get("id") == sigma_id:
            return d
    # Single-doc file whose id wasn't matched still returns the doc.
    return docs[0] if docs else {}


def _query_path(out_dir: Path, sigma_path: str) -> Path:
    rel = Path(sigma_path)
    rel = rel.relative_to("rules") if rel.parts[:1] == ("rules",) else rel
    return out_dir / rel.with_suffix(".kql")


def load_artifacts(rule_map_path: Path, out_dir: Path) -> list[Artifact]:
    """Build the ordered artifact list: parser first, then each deployable rule."""
    with open(rule_map_path, encoding="utf-8") as f:
        rule_map = yaml.safe_load(f)

    artifacts: list[Artifact] = []

    parser = rule_map.get("parser") or {}
    parser_name = parser.get("name", "Sysmon")
    parser_file = REPO_ROOT / parser["file"]
    if not parser_file.is_file():
        raise FileNotFoundError(f"parser file missing: {parser['file']}")
    parser_query = parser_file.read_text(encoding="utf-8")
    artifacts.append(
        Artifact(
            kind="function",
            id=PARSER_SAVED_SEARCH_ID,
            body=build_function_body(parser_name, parser_query),
            query=parser_query.strip(),
            label=f"{parser_name} (parser function)",
        )
    )

    for entry in rule_map.get("rules", []):
        if entry.get("target") not in ("parser", "native"):
            continue
        qpath = _query_path(out_dir, entry["sigma_path"])
        if not qpath.is_file():
            raise FileNotFoundError(
                f"{entry['sigma_path']}: generated query missing at {qpath} "
                "(run scripts/convert_sentinel.py first)"
            )
        query = qpath.read_text(encoding="utf-8")
        sigma_doc = _load_sigma_doc(REPO_ROOT / entry["sigma_path"], entry["sigma_id"])
        artifacts.append(
            Artifact(
                kind="rule",
                id=entry["sigma_id"],
                body=build_alert_rule_body(sigma_doc, query, entry.get("techniques", [])),
                query=query.strip(),
                label=sigma_doc.get("title") or entry["sigma_path"],
            )
        )
    return artifacts


# -- deploy flow (mirrors deploy_wazuh_rules.deploy) --------------------------

def _put(client: SentinelClient, art: Artifact) -> None:
    if art.kind == "function":
        client.deploy_function(art.id, art.body)
    else:
        client.deploy_alert_rule(art.id, art.body)


def _readback(client: SentinelClient, art: Artifact) -> Optional[str]:
    if art.kind == "function":
        return client.get_function_query(art.id)
    return client.get_alert_rule_query(art.id)


def deploy(
    client: Optional[SentinelClient],
    rule_map_path: Path,
    out_dir: Path,
    dry_run: bool = False,
    verify_only: bool = False,
) -> int:
    artifacts = load_artifacts(rule_map_path, out_dir)

    print("=" * 60)
    print("SENTINEL DEPLOYMENT")
    print("=" * 60)

    if dry_run:
        for art in artifacts:
            print(f"📄 would deploy [{art.kind}] {art.label} ({len(art.query)} chars)")
        print(f"✅ Dry run — {len(artifacts)} artifact(s), nothing sent")
        return 0

    assert client is not None  # only dry_run may run clientless

    if verify_only:
        ok = True
        for art in artifacts:
            remote = _readback(client, art)
            if remote is not None and _normalise(remote) == _normalise(art.query):
                print(f"✅ {art.label}: remote matches local")
            else:
                print(f"❌ {art.label}: remote {'ABSENT' if remote is None else 'DIFFERS'}")
                ok = False
        return 0 if ok else 1

    for art in artifacts:
        print(f"⬆️  deploying [{art.kind}] {art.label}")
        _put(client, art)
        remote = _readback(client, art)
        if remote is None or _normalise(remote) != _normalise(art.query):
            print(f"❌ {art.label}: readback verification FAILED")
            return 1
        print(f"✅ {art.label}: readback verified")

    print(f"✅ deployed and verified {len(artifacts)} artifact(s)")
    return 0


def main(argv: Optional[list[str]] = None) -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(REPO_ROOT / ".env")
    except ImportError:
        pass

    parser = argparse.ArgumentParser(description="Deploy DaC rules to a Sentinel workspace")
    parser.add_argument("--rule-map", default=str(REPO_ROOT / "sentinel" / "rule_map.yml"))
    parser.add_argument("--out-dir", default=str(REPO_ROOT / "output" / "sentinel"))
    parser.add_argument("--dry-run", action="store_true", help="Show what would deploy")
    parser.add_argument("--verify-only", action="store_true", help="Compare remote to local, no changes")
    args = parser.parse_args(argv)

    try:
        client = None
        if not (args.dry_run):
            client = SentinelClient(SentinelConfig.from_env())
        code = deploy(
            client,
            Path(args.rule_map),
            Path(args.out_dir),
            dry_run=args.dry_run,
            verify_only=args.verify_only,
        )
    except SentinelClientError as e:
        print(f"❌ {e}")
        code = 2
    except (FileNotFoundError, KeyError, yaml.YAMLError) as e:
        print(f"❌ {e}")
        code = 2
    sys.exit(code)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    main()
