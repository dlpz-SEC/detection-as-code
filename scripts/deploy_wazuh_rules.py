#!/usr/bin/env python3
"""
Deploy Detection-as-Code Wazuh rule files to the live manager.

Reads wazuh/rule_map.yml, uploads each referenced XML file via the Manager
API (PUT /rules/files/{name}?overwrite=true), verifies the readback matches
byte-for-byte (modulo line endings), then restarts the manager once and
waits for analysisd to come back - new rules only load after a restart.

The Tier-2 test runner (test_detections_wazuh.py) never restarts anything;
deployment is the only operation that does, and only from this script.

Exit codes: 0 deployed/verified, 1 verification mismatch, 2 infra failure.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

import yaml

from wazuh_client import WazuhClientError, WazuhConfig, WazuhManagerClient


REPO_ROOT = Path(__file__).resolve().parent.parent


def _normalise(text: str) -> str:
    """Line-ending-insensitive compare: Windows checkouts vs API readback."""
    return text.replace("\r\n", "\n").strip()


def load_rule_files(rule_map_path: Path) -> dict[str, str]:
    """Map file basename -> local XML content for every file in the rule map."""
    with open(rule_map_path, encoding="utf-8") as f:
        rule_map = yaml.safe_load(f)

    files: dict[str, str] = {}
    for entry in rule_map.get("rules", []):
        rel_path = entry["wazuh_file"]
        local = REPO_ROOT / rel_path
        if not local.is_file():
            raise FileNotFoundError(f"rule_map references missing file: {rel_path}")
        files[local.name] = local.read_text(encoding="utf-8")
    return files


def deploy(
    client: Optional[WazuhManagerClient],
    rule_map_path: Path,
    dry_run: bool = False,
    verify_only: bool = False,
    restart: bool = True,
) -> int:
    """Run the deployment; returns the process exit code."""
    files = load_rule_files(rule_map_path)

    print("=" * 60)
    print("WAZUH RULE DEPLOYMENT")
    print("=" * 60)

    if dry_run:
        for name, content in files.items():
            print(f"📄 would upload: {name} ({len(content)} bytes)")
        print("✅ Dry run - nothing sent to the manager")
        return 0

    assert client is not None  # only dry_run may run clientless

    if verify_only:
        ok = True
        for name, content in files.items():
            remote = client.get_rule_file(name)
            if _normalise(remote) == _normalise(content):
                print(f"✅ {name}: remote matches local")
            else:
                print(f"❌ {name}: remote DIFFERS from local")
                ok = False
        return 0 if ok else 1

    for name, content in files.items():
        print(f"⬆️  uploading {name} ({len(content)} bytes)")
        client.upload_rule_file(name, content)
        remote = client.get_rule_file(name)
        if _normalise(remote) != _normalise(content):
            print(f"❌ {name}: readback verification FAILED - not restarting")
            return 1
        print(f"✅ {name}: readback verified")

    if restart:
        print("🔄 restarting manager to load rules...")
        client.restart_manager()
        client.wait_until_ready()
        print("✅ manager back up, analysisd running")
    else:
        print("⚠️  --no-restart: rules uploaded but NOT loaded until next restart")

    return 0


def main(argv: Optional[list[str]] = None) -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(REPO_ROOT / ".env")
    except ImportError:
        pass

    parser = argparse.ArgumentParser(description="Deploy DaC Wazuh rules to the live manager")
    parser.add_argument("--rule-map", default=str(REPO_ROOT / "wazuh" / "rule_map.yml"))
    parser.add_argument("--dry-run", action="store_true", help="Show what would be uploaded")
    parser.add_argument("--verify-only", action="store_true", help="Compare remote files to local, no changes")
    parser.add_argument("--no-restart", action="store_true", help="Upload without restarting the manager")
    args = parser.parse_args(argv)

    try:
        client = None
        if not args.dry_run:
            client = WazuhManagerClient(WazuhConfig.from_env())
        code = deploy(
            client,
            Path(args.rule_map),
            dry_run=args.dry_run,
            verify_only=args.verify_only,
            restart=not args.no_restart,
        )
    except WazuhClientError as e:
        print(f"❌ {e}")
        code = 2
    except FileNotFoundError as e:
        print(f"❌ {e}")
        code = 2
    sys.exit(code)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    main()
