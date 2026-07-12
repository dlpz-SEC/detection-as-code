"""
Tests for scripts/test_detections.py

Covers the SPL search-expression evaluator (field=value with wildcards,
IN membership, NOT(...) filter groups, nested boolean logic), the sigma-cli
noise stripping, technique-based sample<->rule routing, and an end-to-end
check that the committed sample files actually fire (or don't fire) the rules
they target under the REAL converted Splunk queries.

Imported as a module (`import test_detections as td`) so pytest doesn't try to
collect its ``test_rule`` function or ``Test*`` dataclasses as test items.
"""

import json
from pathlib import Path

import pytest

import test_detections as td


SAMPLES_DIR = Path(__file__).resolve().parent / "samples"

# The REAL Splunk queries the CI produces: `sigma convert --target splunk
# --pipeline sysmon`. Raw strings so the doubled backslashes match the file
# content byte-for-byte (the evaluator unescapes \\ -> \ while tokenizing).
LSASS_SPL = r"""EventID=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("*0x1010*", "*0x1410*", "*0x1F1FFF*", "*0x1FFFFF*", "*0x143A*") NOT (SourceImage IN ("*\\MsMpEng.exe*", "*\\MsSense.exe*", "*\\SenseIR.exe*", "*\\csfalconservice.exe*", "*\\cb.exe*") OR SourceImage IN ("C:\\Windows\\System32\\svchost.exe*", "C:\\Windows\\System32\\wininit.exe*", "C:\\Windows\\System32\\lsass.exe*", "C:\\Windows\\System32\\csrss.exe*") OR (SourceImage="*\\WmiPrvSE.exe" SourceImage="C:\\Windows\\System32\\*") OR SourceImage IN ("*\\VeeamAgent*", "*\\Veritas*", "*\\CommVault*"))"""

PS_SPL = r"""EventID=1 Image IN ("*\\powershell.exe", "*\\pwsh.exe") CommandLine IN ("* -enc *", "* -en *", "* -e *", "* -ec *", "* -encodedcommand *", "* -EncodedCommand *") CommandLine IN ("*-nop*", "*-noni*", "*-w hidden*", "*-windowstyle h*", "*-ep bypass*", "*-exec bypass*") NOT ((ParentImage IN ("*\\ccmexec.exe*", "*\\CcmExec.exe*") CommandLine="*-ExecutionPolicy*") OR ParentImage IN ("*\\waappagent.exe*", "*\\WindowsAzureGuestAgent.exe*") OR ParentImage="*\\Microsoft.Management.Services*" OR CommandLine="*Start-DscConfiguration*")"""


@pytest.fixture
def evaluator():
    return td.QueryEvaluator()


def matches(evaluator, query, event):
    """True if the single event matches the query."""
    return bool(evaluator.evaluate(query, [event]))


def load_sample(rel: str) -> td.TestSample:
    return td.TestSample.load(SAMPLES_DIR / rel)


# ---------------------------------------------------------------------------
# Technique extraction + routing
# ---------------------------------------------------------------------------

def test_extract_rule_techniques_strips_tactics_and_prefix():
    tags = ["attack.credential_access", "attack.t1003", "attack.t1003.001"]
    assert td.extract_rule_techniques(tags) == {"T1003", "T1003.001"}


def test_extract_rule_techniques_handles_non_list():
    assert td.extract_rule_techniques(None) == set()
    assert td.extract_rule_techniques("attack.t1003") == set()


@pytest.mark.parametrize(
    "sample_tech,rule_techs,expected",
    [
        ("T1003.001", {"T1003", "T1003.001"}, True),   # exact match
        ("T1059.001", {"T1003.001"}, False),           # different technique
        ("T1003.001", None, True),                     # unresolved rule -> don't filter
        (None, {"T1003.001"}, False),                  # sample can't be routed
        ("T1003", {"T1003.001"}, True),                # sample technique, rule sub-technique
        ("T1003.001", {"T1003"}, True),                # sample sub-technique, rule technique
        ("t1003.001", {"T1003.001"}, True),            # case-insensitive
    ],
)
def test_technique_applies(sample_tech, rule_techs, expected):
    assert td.technique_applies(sample_tech, rule_techs) is expected


# ---------------------------------------------------------------------------
# Core evaluator behavior
# ---------------------------------------------------------------------------

def test_eq_wildcard_is_case_insensitive(evaluator):
    q = r'TargetImage="*\\lsass.exe"'
    assert matches(evaluator, q, {"TargetImage": r"C:\Windows\System32\lsass.exe"})
    assert matches(evaluator, q, {"TargetImage": r"C:\Windows\System32\LSASS.EXE"})
    assert not matches(evaluator, q, {"TargetImage": r"C:\Windows\System32\svchost.exe"})


def test_eq_without_wildcard_is_exact(evaluator):
    assert matches(evaluator, "EventID=10", {"EventID": 10})
    assert not matches(evaluator, "EventID=10", {"EventID": 1})


def test_missing_field_never_matches(evaluator):
    # A process_creation event has no GrantedAccess field.
    assert not matches(evaluator, 'GrantedAccess IN ("*0x1010*")', {"EventID": 1})


def test_in_membership_matches_any_wildcard_value(evaluator):
    q = 'GrantedAccess IN ("*0x1010*", "*0x1410*", "*0x1F1FFF*")'
    assert matches(evaluator, q, {"GrantedAccess": "0x1410"})
    assert not matches(evaluator, q, {"GrantedAccess": "0x1000"})


def test_not_group_negates_whole_expression(evaluator):
    q = 'TargetImage="lsass.exe" NOT (SourceImage IN ("*\\\\MsMpEng.exe*"))'
    # SourceImage in the exclusion list -> filtered out
    assert not matches(evaluator, q, {"TargetImage": "lsass.exe",
                                      "SourceImage": r"C:\Program Files\MsMpEng.exe"})
    # SourceImage not excluded -> still matches
    assert matches(evaluator, q, {"TargetImage": "lsass.exe",
                                  "SourceImage": r"C:\Temp\evil.exe"})


def test_or_and_precedence(evaluator):
    # implicit AND binds tighter than OR: (A AND B) OR C
    q = 'a=1 b=2 OR c=3'
    assert matches(evaluator, q, {"a": "1", "b": "2"})       # left AND true
    assert matches(evaluator, q, {"c": "3"})                 # right true
    assert not matches(evaluator, q, {"a": "1", "c": "9"})   # neither branch true


# ---------------------------------------------------------------------------
# Real LSASS query
# ---------------------------------------------------------------------------

def test_lsass_query_detects_mimikatz(evaluator):
    event = {
        "EventID": 10,
        "SourceImage": r"C:\Users\jdoe\AppData\Local\Temp\mimikatz.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1010",
    }
    assert matches(evaluator, LSASS_SPL, event)


def test_lsass_query_excludes_defender(evaluator):
    event = {
        "EventID": 10,
        "SourceImage": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1410",
    }
    assert not matches(evaluator, LSASS_SPL, event)


def test_lsass_query_ignores_non_suspicious_access(evaluator):
    # Right target, wrong access mask -> selection_access_rights fails.
    event = {
        "EventID": 10,
        "SourceImage": r"C:\Temp\tool.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1000",
    }
    assert not matches(evaluator, LSASS_SPL, event)


def test_lsass_query_excludes_system_svchost(evaluator):
    event = {
        "EventID": 10,
        "SourceImage": r"C:\Windows\System32\svchost.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1410",
    }
    assert not matches(evaluator, LSASS_SPL, event)


# ---------------------------------------------------------------------------
# Real PowerShell query
# ---------------------------------------------------------------------------

def test_powershell_query_detects_encoded_command(evaluator):
    event = {
        "EventID": 1,
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
    }
    assert matches(evaluator, PS_SPL, event)


def test_powershell_query_excludes_sccm_parent(evaluator):
    event = {
        "EventID": 1,
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "ParentImage": r"C:\Windows\CCM\CcmExec.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBF -ExecutionPolicy Bypass",
    }
    assert not matches(evaluator, PS_SPL, event)


def test_powershell_query_ignores_lsass_event(evaluator):
    # The Mimikatz process_access event has no Image/CommandLine fields, so the
    # PowerShell rule must not fire on it (this is why routing matters).
    event = {
        "EventID": 10,
        "SourceImage": r"C:\Temp\mimikatz.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1010",
    }
    assert not matches(evaluator, PS_SPL, event)


# ---------------------------------------------------------------------------
# sigma-cli noise / selector stripping
# ---------------------------------------------------------------------------

def test_parsing_banner_is_stripped(evaluator):
    # A conversion that redirected 2>&1 prepends this stderr banner.
    polluted = "Parsing Sigma rules\n" + LSASS_SPL
    event = {
        "EventID": 10,
        "SourceImage": r"C:\Temp\mimikatz.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1010",
    }
    assert matches(evaluator, polluted, event)


def test_index_selector_prefix_stripped(evaluator):
    q = 'index=windows EventID=10 GrantedAccess IN ("*0x1010*")'
    assert matches(evaluator, q, {"EventID": 10, "GrantedAccess": "0x1010"})


# ---------------------------------------------------------------------------
# End-to-end: committed sample files against the real converted queries
# ---------------------------------------------------------------------------

def test_committed_mimikatz_sample_fires_lsass_rule(evaluator):
    sample = load_sample("true_positives/mimikatz_lsass_access.json")
    assert sample.technique_id == "T1003.001"
    assert evaluator.evaluate(LSASS_SPL, sample.events), "Mimikatz sample must fire the LSASS rule"


def test_committed_benign_sample_does_not_fire_lsass_rule(evaluator):
    sample = load_sample("benign/legitimate_lsass_access.json")
    assert not evaluator.evaluate(LSASS_SPL, sample.events), "Benign Defender scan must not fire"


def test_committed_powershell_sample_fires_powershell_rule(evaluator):
    sample = load_sample("true_positives/powershell_encoded_command.json")
    assert sample.technique_id == "T1059.001"
    assert evaluator.evaluate(PS_SPL, sample.events), "Encoded-command sample must fire the PS rule"


def test_benign_sample_does_not_fire_powershell_rule(evaluator):
    # Cross-rule: the benign LSASS event must not fire the PowerShell rule either.
    sample = load_sample("benign/legitimate_lsass_access.json")
    assert not evaluator.evaluate(PS_SPL, sample.events)


# ---------------------------------------------------------------------------
# test_rule() routing integration
# ---------------------------------------------------------------------------

def _tp(name, technique_id, events):
    return td.TestSample(name=name, filepath=f"<{name}>", event_type="true_positive",
                         technique_id=technique_id, events=events)


def _benign(name, events):
    return td.TestSample(name=name, filepath=f"<{name}>", event_type="benign",
                         technique_id=None, events=events)


def _write_query(tmp_path, spl) -> Path:
    qf = tmp_path / "lsass_memory_access.txt"
    qf.write_text(spl, encoding="utf-8")
    return qf


def test_test_rule_passes_when_routed_by_technique(tmp_path):
    """LSASS rule: only the T1003.001 sample is counted; benign excluded -> pass."""
    qf = _write_query(tmp_path, LSASS_SPL)
    mimikatz = _tp("Mimikatz", "T1003.001",
                   [{"EventID": 10, "SourceImage": r"C:\Temp\mimikatz.exe",
                     "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1010"}])
    powershell = _tp("PS Encoded", "T1059.001",
                     [{"EventID": 1, "Image": r"C:\...\powershell.exe",
                       "ParentImage": r"C:\Windows\System32\cmd.exe",
                       "CommandLine": "powershell -nop -w hidden -enc AAAA"}])
    defender = _benign("Defender",
                       [{"EventID": 10,
                         "SourceImage": r"C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe",
                         "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1410"}])

    result = td.test_rule(qf, [mimikatz, powershell], [defender],
                          td.QueryEvaluator(), rule_techniques={"T1003.001"})

    assert result.passed
    assert result.true_positives_total == 1        # PowerShell sample not counted
    assert result.true_positives_detected == 1
    assert result.false_positives == 0


def test_test_rule_fails_without_routing(tmp_path):
    """Without routing (techniques=None) the PowerShell sample is (wrongly)
    tested against the LSASS query and can't be detected -> the rule fails.
    This is the exact structural bug the technique routing fixes."""
    qf = _write_query(tmp_path, LSASS_SPL)
    mimikatz = _tp("Mimikatz", "T1003.001",
                   [{"EventID": 10, "SourceImage": r"C:\Temp\mimikatz.exe",
                     "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1010"}])
    powershell = _tp("PS Encoded", "T1059.001",
                     [{"EventID": 1, "Image": r"C:\...\powershell.exe",
                       "CommandLine": "powershell -enc AAAA"}])

    result = td.test_rule(qf, [mimikatz, powershell], [], td.QueryEvaluator(),
                          rule_techniques=None)

    assert not result.passed
    assert result.true_positives_total == 2
    assert result.true_positives_detected == 1
