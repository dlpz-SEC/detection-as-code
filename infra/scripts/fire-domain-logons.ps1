<#
    Live-fire the lab domain: generate real domain authentication telemetry.

    Run on the domain controller AFTER seed-ad.ps1, to prove the whole chain end
    to end - a real domain logon on a real DC, collected by the DCR, landing in
    the Log Analytics workspace, in the exact shape the rule corpus keys on.

    WHY THIS EXISTS AS A FILE. Firing test authentication by hand from a console
    is not reproducible and leaves no record of what was fired or when. The
    evidence for a detection is only as good as the account of what produced it,
    so the trigger is version-controlled alongside the rule it validates. Same
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
    (pre-authentication failed). Measured, not assumed: a 2026-09-04 run produced
    exactly 8x 4625 and 0x 4771.

    That is fine for the two rules in rules/ - both select EventID 4625, so the
    telemetry they consume is genuinely produced. It is NOT sufficient to prove
    the Kerberos collection path. Doing that needs authentication from a
    domain-JOINED member host over Kerberos, which needs a second VM; until then
    4768/4771 are configured and deployed but unexercised, and any claim about
    them should say so.

    CREDENTIAL HANDLING. The password arrives as a parameter and is used only to
    produce ONE successful validation. The wrong password is a fixed literal that
    is never a real credential. Every account here is a disposable lab object in
    a non-routable domain; see the warning block in seed-ad.ps1.

    SAFETY. This authenticates against the local lab domain only. It cannot reach
    anything outside the forest, and the forest has no trusts. The failure counts
    are deliberately kept under the default lockout threshold so the run does not
    lock the accounts it needs for the success phase.

    RUNNING IT REMOTELY (no RDP), the established pattern from LESSONS.md
    2026-08-28:

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
    # The password seed-ad.ps1 assigned to every lab account. Needed for exactly
    # one successful authentication.
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

    # Failures per account. Default domain lockout threshold is 0 (disabled) on a
    # fresh forest, but keep this low anyway so the script stays safe if someone
    # enables lockout later.
    [ValidateRange(1, 5)]
    [int] $FailuresPerAccount = 3
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
    # produces genuine 4624/4625/4768/4771 records rather than synthetic rows
    # written into a log. That authenticity is the entire point: the evidence has
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

    Write-Step "Now the success, which is what turns noise into an incident."
    $success = $ctx.ValidateCredentials($BruteForceTarget, $LabUserPasswordPlainText)
    if ($success) {
        Write-Step "SUCCESS-AUTH $BruteForceTarget authenticated (expect 4624 + 4768, and 4672 if privileged)"
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
    Write-Output '  4625 / 4771  failed logon / Kerberos pre-auth failed (0x18 = bad password)'
    Write-Output '  4624 / 4768  successful logon / TGT issued'
    Write-Output ("  4672         special privileges, on {0} only" -f $BruteForceTarget)
    Write-Output ''
    Write-Output 'Local check on this DC (the log is a ring buffer, so check soon):'
    Write-Output '  Get-WinEvent -FilterHashtable @{LogName=''Security''; Id=4625,4771,4624,4768,4672; StartTime=(Get-Date).AddMinutes(-15)} |'
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
