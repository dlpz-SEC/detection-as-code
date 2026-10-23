<#
    Live-fire the lab domain: generate real domain authentication telemetry.

    Run on the domain controller AFTER seed-ad.ps1, to prove the telemetry path
    end to end - a real domain logon on a real DC, collected by the DCR, landing
    in the Log Analytics workspace, including the 4625 events that the two
    correlation rules below select. It proves collection, not detection: this
    repo's pipeline cannot deploy either rule to Sentinel; see THRESHOLDS.

    WHY THIS EXISTS AS A FILE. Firing test authentication by hand from a console
    is not reproducible and leaves no record of what was fired or when. The
    evidence for a detection is only as good as the account of what produced it,
    so the trigger is version-controlled alongside the rules it feeds. Same
    reasoning as sysmonconfig.xml being in the repo rather than pasted into a VM.

    WHAT IT MODELS. Two attack shapes, chosen because rules/ already contains a
    detection for each. This is deliberately not a generic noise generator:

      1. PASSWORD SPRAY  -> rules/windows/credential_access/password_spray_single_source.yml
         One source, one wrong password, tried against MANY distinct accounts.
         The signal is breadth: several usernames failing from one origin in a
         short window. Real spraying keeps the count per account below the
         lockout threshold, which is exactly why account-lockout alerting misses
         it and why the rule counts distinct targets instead.

      2. BRUTEFORCE THEN SUCCESS -> rules/windows/credential_access/bruteforce_failures_then_success.yml
         One account, repeated failures, then a SUCCESS. The success is the part
         that matters: failures alone are noise, failures followed by a valid
         logon from the same source is a compromised credential. The rule asks
         the analyst to confirm the subsequent 4624, which is why the DCR
         collects 4624 as investigation context even though no rule selects it.

    WHAT THE DC EMITS AS A RESULT. Corrected 2026-09-04 against an actual run;
    the original version of this comment predicted Kerberos events and was wrong.

      Failures  -> 4625 (failed logon) and 4776 (NTLM credential validation).
      Success   -> 4624 (successful logon), 4776, and 4672 IF the account is
                   privileged. m.okafor is in Domain Admins for this reason - it
                   makes privileged and unprivileged logons distinguishable in
                   the telemetry rather than a matter of looking the account up
                   afterwards.

    WHY NTLM AND NOT KERBEROS, which matters if you are trying to exercise the
    Kerberos half of the DCR. ValidateCredentials negotiates, and a bind issued
    ON the domain controller against its own domain settles on NTLM. So a run of
    this script produces 4625/4776 and does NOT produce 4768 (TGT issued) or 4771
    (pre-authentication failed). Measured, not assumed: the 2026-09-04 run, made
    at the then-default of 3 brute-force failures (5 spray + 3 = 8 failed
    validations), left exactly 8x 4625 and 0x 4771 in the DC's Security log,
    one 4625 per failed validation. The default is now 5, so a default run makes
    10 failed validations; 10x 4625 is expected but has not been measured.

    That is fine for the two 4625-based rules in rules/ - both select EventID
    4625, so the telemetry they are written against is genuinely produced. It is
    NOT sufficient to prove the Kerberos collection path. Doing that needs
    authentication from a domain-JOINED member host over Kerberos, which needs a
    second VM; until then 4768/4771 are configured in the DCR but unexercised,
    and any claim about them should say so.

    THRESHOLDS. Both correlations count 4625 within 1h, with gte: 5. The spray
    rule counts distinct TargetUserName per IpAddress. A bind issued on the DC
    recorded the DC's own private IP there (10.20.0.4 on all 8 rows of
    docs/evidence/sentinel-livefire-query.json), so one group holds the 5 spray
    targets plus the brute-force target, and the 2026-09-04 run already met it.
    The brute-force rule counts 4625 per TargetUserName; that run made 3 for
    m.okafor and did not meet it, which is why the default is now 5. Meeting a
    threshold raises no alert from these rules: both are target: none in
    sentinel/rule_map.yml (the kusto backend cannot convert correlations), so
    this repo deploys no Sentinel analytics rule for either.

    CREDENTIAL HANDLING. The password arrives as a parameter and is used only for
    the two successful validations: the brute-force target, then the contrast
    account. The wrong password is a fixed literal plus a random four-digit
    suffix, and is never a real credential. Every account here is a disposable
    lab object in a non-routable domain; see the warning block in seed-ad.ps1.

    SAFETY. This authenticates against the local lab domain only. It cannot reach
    anything outside the forest, and the forest has no trusts. It does not rely
    on staying under a lockout threshold: Microsoft documents the Default Domain
    Policy threshold as 0 (never lock), and the lab scripts do not change it. If
    lockout has been enabled at or below the failures an account takes
    (-FailuresPerAccount for the brute-force target, one per spray target), that
    account locks, and any success the script then attempts for it fails. See
    the -FailuresPerAccount comment.

    RUNNING IT REMOTELY (no RDP), the same az vm run-command pattern as
    seed-ad.ps1 (the VM must be running):

      az vm run-command invoke -g sc200-lab-rg -n sc200-win-vm \
        --command-id RunPowerShellScript \
        --scripts "@infra/scripts/fire-domain-logons.ps1" \
        --parameters "LabUserPasswordPlainText=<the seed password>" \
        --query "value[0].message" -o tsv

    Note the UTC timestamps it prints. Ingestion is not instant: AMA batches, and
    rows typically appear in the workspace within 2-10 minutes. Use the printed
    window to bound the KQL rather than guessing at ago().
#>

[CmdletBinding()]
param(
    # The password seed-ad.ps1 assigned to every lab account. Needed for the two
    # successful authentications: the brute-force target and the contrast account.
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $LabUserPasswordPlainText,

    # The account used for the bruteforce-then-success shape. Defaults to the
    # Domain Admins member, so the success also produces 4672 and the evidence
    # shows a privileged logon rather than only a standard one.
    [ValidateNotNullOrEmpty()]
    [string] $BruteForceTarget = 'm.okafor',

    # Accounts to spray. Kept to unprivileged users: a spray that only ever
    # targets admins is not what spraying looks like.
    [string[]] $SprayTargets = @('a.chen', 'p.novak', 't.walsh', 'j.reyes', 'svc-backup'),

    # Failed validations against $BruteForceTarget before its success. Despite
    # the name, only the brute-force target gets this many; each spray target
    # gets exactly one. Default 5 because that is the brute-force correlation's
    # threshold (event_count gte: 5 per TargetUserName within 1h), so a default
    # run is meant to reach it. The cap is the same 5: going higher adds lockout
    # exposure and no detection value. Change both if the rule threshold moves.
    # Lockout: Microsoft documents the Default Domain Policy threshold as 0
    # (never lock). If lockout is enabled at a threshold at or below this value,
    # the target locks before the success phase. Setting this below the lockout
    # threshold avoids that, at the cost of a single run no longer meeting the
    # rule's threshold.
    [ValidateRange(1, 5)]
    [int] $FailuresPerAccount = 5
)

$ErrorActionPreference = 'Stop'
$transcript = 'C:\Windows\Temp\fire-domain-logons.log'
Start-Transcript -Path $transcript -Append | Out-Null

function Write-Step { param([string] $Message) Write-Output "[fire] $Message" }

# A password that is wrong by construction. Never a real credential.
$wrongPassword = 'DefinitelyNotThePassword!' + (Get-Random -Minimum 1000 -Maximum 9999)

try {
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    $domain = Get-ADDomain -ErrorAction Stop
    $dnsRoot = $domain.DNSRoot
    Write-Step "Domain: $dnsRoot"
    Write-Step "Source host: $env:COMPUTERNAME"

    $startUtc = (Get-Date).ToUniversalTime()
    Write-Step ("WINDOW START (UTC): {0:yyyy-MM-ddTHH:mm:ssZ}" -f $startUtc)

    # ValidateCredentials performs a real authentication against the DC, so it
    # produces genuine records (4625/4776 on failure, 4624 on success; NTLM, see
    # the header) rather than synthetic rows written into a log. That
    # authenticity is the entire point: the evidence has
    # to be indistinguishable from production telemetry.
    $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext(
        [System.DirectoryServices.AccountManagement.ContextType]::Domain, $dnsRoot)

    # ------------------------------------------------------------------
    # Phase 1 - password spray. Breadth, not depth.
    # ------------------------------------------------------------------
    Write-Step '--- Phase 1: password spray (many accounts, one wrong password) ---'
    $sprayFailures = 0
    foreach ($user in $SprayTargets) {
        try {
            $ok = $ctx.ValidateCredentials($user, $wrongPassword)
            if ($ok) {
                # Would mean the throwaway string is the real password. Absurd,
                # but report it rather than silently counting it as a failure.
                Write-Step "UNEXPECTED  $user validated with the wrong password"
            }
            else {
                $sprayFailures++
                Write-Step "FAILED-AUTH $user (expected: this is the spray)"
            }
        }
        catch {
            $sprayFailures++
            Write-Step "FAILED-AUTH $user (exception: $($_.Exception.Message))"
        }
        Start-Sleep -Milliseconds 400
    }

    # ------------------------------------------------------------------
    # Phase 2 - bruteforce then success. Depth, then the payoff.
    # ------------------------------------------------------------------
    Write-Step "--- Phase 2: bruteforce then success ($BruteForceTarget) ---"
    $bruteFailures = 0
    for ($i = 1; $i -le $FailuresPerAccount; $i++) {
        try {
            $null = $ctx.ValidateCredentials($BruteForceTarget, $wrongPassword)
            $bruteFailures++
            Write-Step "FAILED-AUTH $BruteForceTarget attempt $i of $FailuresPerAccount"
        }
        catch {
            $bruteFailures++
            Write-Step "FAILED-AUTH $BruteForceTarget attempt $i (exception)"
        }
        Start-Sleep -Milliseconds 400
    }

    Write-Step "Now the success, which is what turns noise into a compromised credential."
    $success = $ctx.ValidateCredentials($BruteForceTarget, $LabUserPasswordPlainText)
    if ($success) {
        Write-Step "SUCCESS-AUTH $BruteForceTarget authenticated (expect 4624 + 4776, and 4672 if privileged)"
    }
    else {
        Write-Step "PROBLEM: $BruteForceTarget did NOT authenticate. Wrong LabUserPasswordPlainText?"
        Write-Step "The failure telemetry above is still valid; only the success half is missing."
    }

    # One more clean success on an unprivileged account, so the evidence shows
    # the CONTRAST: a 4624 with 4672 alongside one without.
    $contrastUser = $SprayTargets[0]
    $contrastOk = $ctx.ValidateCredentials($contrastUser, $LabUserPasswordPlainText)
    Write-Step ("CONTRAST-AUTH {0} success={1} (expect 4624 WITHOUT 4672)" -f $contrastUser, $contrastOk)

    $endUtc = (Get-Date).ToUniversalTime()

    Write-Output ''
    Write-Output '=============================================================='
    Write-Output ' LIVE FIRE SUMMARY'
    Write-Output '=============================================================='
    Write-Output ("Domain              : {0}" -f $dnsRoot)
    Write-Output ("Source host         : {0}" -f $env:COMPUTERNAME)
    Write-Output ("Window start (UTC)  : {0:yyyy-MM-ddTHH:mm:ssZ}" -f $startUtc)
    Write-Output ("Window end   (UTC)  : {0:yyyy-MM-ddTHH:mm:ssZ}" -f $endUtc)
    Write-Output ''
    Write-Output ("Spray failures      : {0} across {1} accounts" -f $sprayFailures, $SprayTargets.Count)
    Write-Output ("Bruteforce failures : {0} against {1}" -f $bruteFailures, $BruteForceTarget)
    Write-Output ("Bruteforce success  : {0}" -f $success)
    Write-Output ("Contrast success    : {0} ({1})" -f $contrastOk, $contrastUser)
    Write-Output ''
    Write-Output 'Expected in the Security log now, and in the workspace shortly:'
    Write-Output '  4625 / 4776  failed logon / NTLM credential validation'
    Write-Output '  4624 / 4776  successful logon / NTLM credential validation'
    Write-Output ('  4672         special privileges: {0} if privileged; other accounts too, such as {1}$ (the DC computer account)' -f $BruteForceTarget, $env:COMPUTERNAME)
    Write-Output '  (No 4768/4771: a bind issued on the DC itself settles on NTLM. See the header.)'
    Write-Output ''
    Write-Output 'Local check on this DC (the log is a ring buffer, so check soon):'
    Write-Output '  Get-WinEvent -FilterHashtable @{LogName=''Security''; Id=4625,4776,4624,4672; StartTime=(Get-Date).AddMinutes(-15)} |'
    Write-Output '    Group-Object Id | Select-Object Name, Count'
    Write-Output ''
    Write-Output ("Transcript          : {0}" -f $transcript)
    Write-Output '=============================================================='

    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Step "FAILED: $($_.Exception.Message)"
    Write-Step "Transcript: $transcript"
    Stop-Transcript | Out-Null
    exit 1
}
