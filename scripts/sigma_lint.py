#!/usr/bin/env python3
"""
Run `sigma check --fail-on-issues` against a PINNED MITRE ATT&CK release.

Why this wrapper exists: pySigma's ATT&CK tag validator does not ship its own
copy of ATT&CK. It downloads enterprise-attack.json from the MASTER branch of
mitre-attack/attack-stix-data and caches it under one fixed key that never
expires. So the set of "valid" tactic and technique tags depends on when the
cache was first filled: a laptop with an old cache and a fresh CI runner can
disagree about the same rule. ATT&CK v19 renamed TA0005 Defense Evasion to
Stealth, which is exactly how `attack.defense-evasion` passed locally and
failed on a clean runner.

This script points pySigma at one specific, versioned release file, checks
its SHA-256, and keeps it in a version-specific cache directory. Lint results
are then reproducible, and moving to a newer ATT&CK release is a deliberate
edit of ATTACK_VERSION and ATTACK_SHA256 here, not something CI discovers.

Usage:
    python scripts/sigma_lint.py rules/
    python scripts/sigma_lint.py rules/windows/execution/powershell_encoded_command.yml

Needs the Sigma toolchain from scripts/requirements-sigma.txt.
"""

import hashlib
import sys
from pathlib import Path
from urllib.request import urlretrieve

ATTACK_VERSION = "19.1"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
ATTACK_SHA256 = "bdf1ce86a4e604214c5076d37ae4dcb322678afc528df8492e6fdc1b554f5da3"
CACHE_DIR = Path.home() / ".cache" / "detection-as-code" / f"attack-{ATTACK_VERSION}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pinned_attack_file(cache_dir: Path = CACHE_DIR) -> Path:
    """Return the verified local copy of the pinned ATT&CK bundle, downloading
    it once if absent. A hash mismatch is fatal: a silently different bundle
    is the failure this script exists to prevent."""
    path = cache_dir / f"enterprise-attack-{ATTACK_VERSION}.json"
    if not path.is_file():
        cache_dir.mkdir(parents=True, exist_ok=True)
        partial = path.with_name(path.name + ".part")
        urlretrieve(ATTACK_URL, partial)
        partial.replace(path)
    actual = _sha256(path)
    if actual != ATTACK_SHA256:
        raise RuntimeError(
            f"ATT&CK {ATTACK_VERSION} bundle at {path} has SHA-256 {actual}, "
            f"expected {ATTACK_SHA256}. Delete the file to re-download, or "
            "update ATTACK_SHA256 deliberately if the pin itself changed."
        )
    return path


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit("usage: sigma_lint.py <rule file or directory> [...]")
    attack_file = pinned_attack_file()

    # Imported late so this module (and its tests) load without pySigma.
    from sigma.data import mitre_attack
    from sigma.cli.main import main as sigma_main

    # The cache directory first: set_url() clears whichever cache is active,
    # and the user's default pySigma cache is not ours to wipe.
    mitre_attack.set_cache_dir(str(CACHE_DIR / "pysigma"))
    mitre_attack.set_url(str(attack_file))
    print(f"ATT&CK data pinned to {ATTACK_VERSION} ({attack_file})")
    # sigma-cli's entry point takes no arguments and reads sys.argv itself.
    sys.argv = ["sigma", "check", "--fail-on-issues", *argv]
    sigma_main()


if __name__ == "__main__":
    main(sys.argv[1:])
