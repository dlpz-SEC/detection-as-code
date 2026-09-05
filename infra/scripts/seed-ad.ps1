<#
    Seed the lab domain controller with real Active Directory structure.

    Run AFTER the VM has finished the restart that completes promotion (see
    infra/modules/promote-dc.ps1). A freshly promoted DC is an empty directory:
    one domain, the built-in containers, and the accounts AD DS creates for
    itself. Nothing about that looks like an administered environment, and
    almost none of the authentication telemetry a detection needs exists yet,
    because a domain with no users and no service accounts produces no
    interesting Kerberos traffic.

    WHAT THIS PROVES. Three things, in the order they matter for the portfolio:

      1. The DC is ADMINISTERED, not just promoted. An OU tree that separates
         workstations, servers, service accounts and people; security groups
         with real membership; users placed where a GPO or a delegation would
         actually target them. This is the difference between "I clicked
         Install-ADDSForest" and "I run a directory".

      2. Privileged and unprivileged are DISTINGUISHABLE IN THE TELEMETRY. One
         account is a member of Domain Admins. With the Special Logon
         subcategory enabled below, that account's logons carry 4672 and the
         other six do not. A detection that cannot tell an admin logon from a
         helpdesk logon is not a detection, it is a counter.

      3. Kerberoasting becomes DETECTABLE. Section 4 registers a Service
         Principal Name on a normal user account. That single attribute is what
         makes the account appear in an attacker's `setspn -T <domain> -Q */*`
         or GetUserSPNs sweep, and what makes a service-ticket request against
         it show up as 4769. configs/coverage_config.yml lists T1558.003
         (Kerberoasting) as a CRITICAL priority technique with no rule in
         rules/ covering it. This script creates the object that a T1558.003
         rule would have nothing to fire on otherwise. It is the single most
         portfolio-relevant thing in this file.

    EVENT IDs THIS CAUSES THE DC TO EMIT. Two distinct groups, and the
    distinction matters:

    (a) Emitted DURING this script's own run, as a side effect of creating the
        objects (once Section 5's audit policy is in place - on a re-run the
        policy is already set, so a re-run is also the first run that captures
        its own object creation cleanly):
          4720  user account created            (per user, x7)
          4722  user account enabled
          4724  attempt to reset a password     (New-ADUser sets one)
          4738  user account changed            (SPN registration in Section 4)
          4727  security-enabled global group created  (IT-Admins, Finance-ReadOnly)
          4728  member added to a security-enabled GLOBAL group
                (including the Domain Admins addition - Domain Admins is a
                 global group, so it is 4728 and not 4732; 4732 is the
                 domain-local/built-in form and this script creates none)
          4662  operation performed on a directory object (SACL-gated, see below)

    (b) Emitted FROM NOW ON, because Section 5 turns the subcategories on. These
        are the events the lab actually exists to collect:
          4624  successful logon
          4625  failed logon
          4648  logon using explicit credentials
          4634  logoff
          4647  user-initiated logoff
          4672  special privileges assigned to new logon  <- the admin marker
          4740  account locked out
          4767  account unlocked
          4768  Kerberos TGT requested
          4769  Kerberos SERVICE ticket requested          <- the Kerberoast signal
          4770  Kerberos service ticket renewed
          4771  Kerberos pre-authentication failed
          4772  Kerberos TGT request failed
          4773  Kerberos service ticket request failed
          4741  computer account created   (when a workstation joins)
          4742  computer account changed
          4743  computer account deleted

    WHAT THE CORPUS ACTUALLY CONSUMES TODAY. Verified against rules/, not
    assumed: 4625 feeds both credential-access correlations
    (bruteforce_failures_then_success, password_spray_single_source) and 4624 is
    collected as investigation context. Every other ID in the list above is
    emitted but has no consuming rule yet. That is deliberate: emitting is free,
    ingesting is not.

    COST. This script costs nothing to run. The audit policy it sets is where
    the money is, and it is worth being blunt about the shape of it:

      - A domain controller sees EVERY authentication in the domain. 4624 and
        4768 volume from a DC is not comparable to 4624 volume from a member
        server. The lab's workspace has a 1 GB/day ingestion cap
        (infra/main.bicepparam), and that cap overshoots.
      - The DCR (infra/modules/dcr.bicep) currently collects only 4624, 4625 and
        Sysmon EID 1/10. So 4768 and 4769 are EMITTED to the local Security log
        by this script and are NOT ingested into Sentinel. Nothing is broken;
        that is the current, deliberate scope. Adding the Kerberos IDs to the
        DCR's XPath list is a spending decision, not a config tweak - make it
        alongside the T1558.003 rule that needs them, not before.
      - The local Security event log is a ring buffer. A DC with these
        subcategories on can roll it faster than you expect. Check the current
        size and retention with `wevtutil gl Security` before assuming an event
        from an hour ago is still there.
      - The DC VM itself is the compute bill. Deallocate it between live-fire
        runs (`az vm deallocate`); a Sentinel scheduled rule fires from
        already-ingested rows, so the VM does not need to be up for the
        detection to raise.

    WARNING - LAB CREDENTIALS, NON-ROUTABLE DOMAIN.

      Every account created here shares one password, supplied as a parameter.
      That is a lab convenience and nothing else: it means one compromised
      account is all seven, and it exists so a live-fire test can authenticate
      as any of them without a credential store. Use a throwaway value. Never
      reuse a password you use anywhere real, and never treat these accounts as
      a model of how to provision users.

      The domain (`lab.dlpz.local` by default, see main.bicep) is non-routable
      by design: `.local` is not delegable on the public internet, the DC lives
      behind a fail-closed NSG, and the forest has no trust to anything. It is a
      disposable directory inside a burst lab that gets deleted with
      `az group delete`.

      The accounts are deliberately PasswordNeverExpires. The default domain
      password policy expires passwords at 42 days, and a lab that outlives that
      would start producing authentication failures that look like a finding and
      are not.

    IDEMPOTENCE. Safe to re-run. Every create is preceded by an existence check,
    so a second run reports "exists" and changes nothing. There is no -WhatIf:
    the script IS the dry run, because a re-run against a seeded domain is a
    no-op that prints the current state. Objects that already exist are NOT
    reconciled - if you rename an OU or move a user by hand, this script will
    report the object missing and create a second one rather than fixing yours.

    RUNNING IT REMOTELY (no RDP). The established pattern for this lab, from
    LESSONS.md 2026-08-28: drive the VM through the control plane from an
    already-authenticated Cloud Shell instead of opening an RDP client and
    fetching the admin password.

      # The VM must be RUNNING. az vm run-command fails with
      # OperationNotAllowed on a deallocated VM, and a recent telemetry
      # timestamp is NOT evidence that it is up (LESSONS.md 2026-08-28).
      az vm start -g sc200-lab-rg -n sc200-win-vm

      # Run from the REPO ROOT on a branch that actually has this file, or the
      # @-relative path resolves to nothing (LESSONS.md 2026-08-28).
      az vm run-command invoke \
        --resource-group sc200-lab-rg \
        --name sc200-win-vm \
        --command-id RunPowerShellScript \
        --scripts @infra/scripts/seed-ad.ps1 \
        --parameters "LabUserPasswordPlainText=<throwaway-strong-password>"

    Two honest caveats about that invocation:

      - run-command has no SecureString transport. The value passed to
        -LabUserPasswordPlainText travels in the ARM request body and lands in
        your shell history. It is encrypted in transit and Azure does not return
        it from a GET, but treat it as burned the moment you type it. Same
        posture promote-dc.ps1 takes with -DsrmPassword. When you have an
        interactive session on the DC, use the -LabUserPassword SecureString
        parameter instead; that is the default parameter set for a reason.
      - Azure truncates run-command output, so Section 6's summary is
        deliberately compact. The full transcript is written to
        C:\Windows\Temp\seed-ad.log on the DC.

    AUTHORISATION. Under run-command this executes as NT AUTHORITY\SYSTEM. On a
    domain controller SYSTEM can write to the directory (the domain head's
    default ACL grants SYSTEM full control, inherited by descendants), which is
    why this works without supplying domain credentials. The script does not
    assume it: every create reports its own failure, so if the identity is not
    permitted you get an error naming the object rather than a silent partial
    seed. If that happens, run it from an elevated Domain Admin session on the
    DC instead.
#>

[CmdletBinding(DefaultParameterSetName = 'SecurePassword')]
param(
    # Preferred. Use this from an interactive session on the DC:
    #   .\seed-ad.ps1 -LabUserPassword (Read-Host -AsSecureString)
    [Parameter(Mandatory = $true, ParameterSetName = 'SecurePassword')]
    [SecureString] $LabUserPassword,

    # Only for `az vm run-command`, which cannot carry a SecureString. See the
    # caveat in the header: this value is exposed in the ARM request and in
    # shell history. Throwaway values only.
    [Parameter(Mandatory = $true, ParameterSetName = 'RunCommand')]
    [ValidateNotNullOrEmpty()]
    [string] $LabUserPasswordPlainText,

    # Defaults to the domain this DC hosts. Override only to target a specific
    # naming context; the script never guesses a domain name.
    [ValidateNotNullOrEmpty()]
    [string] $DomainDistinguishedName,

    # The Kerberoastable SPN. Format is service class / host / port. The host
    # part does not need to resolve for the SPN to be registered, to be
    # discoverable by an SPN sweep, or to produce 4769 - Kerberos looks the SPN
    # up in the directory, not in DNS.
    [ValidateNotNullOrEmpty()]
    [string] $ServiceAccountSpnPrefix = 'MSSQLSvc/sqlreport',

    [ValidateRange(1, 65535)]
    [int] $ServiceAccountSpnPort = 1433,

    # Section 5 is the expensive half. Skip it if you only want the objects, or
    # if the DC's audit policy is managed by a GPO you do not want to fight.
    [switch] $SkipAuditPolicy
)

$ErrorActionPreference = 'Stop'
$transcript = 'C:\Windows\Temp\seed-ad.log'
Start-Transcript -Path $transcript -Append | Out-Null

# Counters, so Section 6 can report what this run actually did versus what was
# already there. A re-run that reports 0 created and 0 changed is the proof of
# idempotence.
$script:Created = 0
$script:Existing = 0
$script:Failed = 0

function Write-Step {
    param(
        [string] $Message,
        [ValidateSet('new', 'skip', 'fail', 'info')]
        [string] $Kind = 'info'
    )
    switch ($Kind) {
        'new'  { $script:Created++;  $tag = 'CREATED ' }
        'skip' { $script:Existing++; $tag = 'exists  ' }
        'fail' { $script:Failed++;   $tag = 'FAILED  ' }
        default            { $tag = '        ' }
    }
    Write-Output "[seed-ad] $tag$Message"
}

# ----------------------------------------------------------------------------
# Idempotence helpers.
#
# All of these use -Filter rather than -Identity on the existence check. That is
# not style: Get-AD* -Identity THROWS ADIdentityNotFoundException when the object
# is absent, so an -Identity probe has to be wrapped in a try/catch that would
# also swallow a permissions error. -Filter returns $null for "not found" and
# still throws for anything genuinely wrong, which is the behaviour we want.
#
# None of these return a value, and that is deliberate. Write-Step logs to the
# SUCCESS stream (Write-Output, matching promote-dc.ps1 so run-command and the
# transcript both capture it). A PowerShell function that logs to the success
# stream and also returns a value hands its caller an array of
# [log message, value] - the classic footgun. Making them void removes the
# ambiguity entirely: callers compose the DN they need, which is deterministic.
# ----------------------------------------------------------------------------

function New-LabOu {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string] $ParentPath,
        [string] $Description = ''
    )
    $existing = Get-ADOrganizationalUnit -Filter "Name -eq '$Name'" -SearchBase $ParentPath -SearchScope OneLevel
    if ($existing) {
        Write-Step "OU $Name under $ParentPath"  'skip'
        return
    }
    # -ProtectedFromAccidentalDeletion adds a deny-delete ACE. It is the default
    # for this cmdlet, set explicitly here because it is a decision, not a
    # default worth inheriting silently. Consequence to know: removing one of
    # these OUs by hand needs
    #   Set-ADOrganizationalUnit -Identity <dn> -ProtectedFromAccidentalDeletion $false
    # first. It does not obstruct lab teardown, which is `az group delete` and
    # takes the whole VM with the directory on it.
    New-ADOrganizationalUnit -Name $Name -Path $ParentPath `
        -ProtectedFromAccidentalDeletion $true -Description $Description
    Write-Step "OU $Name under $ParentPath" 'new'
}

function New-LabUser {
    param(
        [Parameter(Mandatory)][string] $Sam,
        [Parameter(Mandatory)][string] $DisplayName,
        [Parameter(Mandatory)][string] $GivenName,
        [Parameter(Mandatory)][string] $Surname,
        [Parameter(Mandatory)][string] $Title,
        [Parameter(Mandatory)][string] $Department,
        [Parameter(Mandatory)][string] $OuPath,
        [Parameter(Mandatory)][SecureString] $Password,
        [string] $Description = ''
    )
    $existing = Get-ADUser -Filter "SamAccountName -eq '$Sam'"
    if ($existing) {
        # Deliberately NOT reconciled. Re-setting the password here would emit a
        # 4724 on every run and would clobber a password the operator may have
        # changed for a specific test.
        Write-Step "user $Sam" 'skip'
        return
    }
    $upn = '{0}@{1}' -f $Sam, $script:DnsRoot
    New-ADUser -Name $DisplayName -SamAccountName $Sam -UserPrincipalName $upn `
        -GivenName $GivenName -Surname $Surname -DisplayName $DisplayName `
        -Title $Title -Department $Department -Description $Description `
        -Path $OuPath -AccountPassword $Password -Enabled $true `
        -ChangePasswordAtLogon $false -PasswordNeverExpires $true
    Write-Step "user $Sam ($Title) in $OuPath" 'new'
}

function New-LabGroup {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string] $OuPath,
        [string] $Description = ''
    )
    $existing = Get-ADGroup -Filter "SamAccountName -eq '$Name'"
    if ($existing) {
        Write-Step "group $Name" 'skip'
        return
    }
    # Global + Security is the scope that produces 4727 on creation and 4728 on
    # membership change. A domain-local group would produce 4731/4732 instead,
    # which is why the event-ID inventory in the header lists 4728 and not 4732.
    New-ADGroup -Name $Name -SamAccountName $Name -GroupCategory Security `
        -GroupScope Global -Path $OuPath -Description $Description
    Write-Step "group $Name in $OuPath" 'new'
}

function Add-LabGroupMember {
    param(
        [Parameter(Mandatory)][string] $GroupIdentity,
        [Parameter(Mandatory)][string] $MemberSam
    )
    $group  = Get-ADGroup -Identity $GroupIdentity
    $member = Get-ADUser -Identity $MemberSam -Properties MemberOf
    # Membership is read off the USER's memberOf rather than the group's member
    # list. Add-ADGroupMember throws when the principal is already a member, so
    # the check has to happen first for the script to stay re-runnable.
    if ($member.MemberOf -contains $group.DistinguishedName) {
        Write-Step "membership $MemberSam in $($group.Name)" 'skip'
        return
    }
    Add-ADGroupMember -Identity $group -Members $member
    Write-Step "membership $MemberSam -> $($group.Name)" 'new'
}

function Set-LabAuditSubcategory {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string] $Guid,
        [bool] $Success = $true,
        [bool] $Failure = $true
    )
    $s = if ($Success) { 'enable' } else { 'disable' }
    $f = if ($Failure) { 'enable' } else { 'disable' }

    # auditpol subcategory NAMES are localised. On the en-US Azure marketplace
    # image this lab uses (2022-datacenter-azure-edition, see vm.bicep) the
    # English names are correct, so they are tried first because they are what a
    # reader can check against Microsoft's documentation. The GUID is the
    # locale-independent fallback for any other image.
    #
    # If you ever land on the GUID path, verify the GUID before trusting it:
    #   auditpol /list /subcategory:* /v
    # prints the name-to-GUID mapping for the DC you are actually on.
    $null = auditpol /set /subcategory:"$Name" /success:$s /failure:$f 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Step "audit $Name (success=$s failure=$f)" 'new'
        return
    }

    $null = auditpol /set /subcategory:"$Guid" /success:$s /failure:$f 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Step "audit $Name via GUID $Guid (success=$s failure=$f)" 'new'
        return
    }

    Write-Step "audit $Name - auditpol rejected both the name and the GUID (exit $LASTEXITCODE)" 'fail'
}

try {
    # ------------------------------------------------------------------
    # 0. Preflight. Fail loudly and early rather than half-seeding.
    # ------------------------------------------------------------------
    if ($PSCmdlet.ParameterSetName -eq 'RunCommand') {
        $LabUserPassword = ConvertTo-SecureString -String $LabUserPasswordPlainText -AsPlainText -Force
        # Drop the plaintext copy. This is hygiene, not protection: the value is
        # already in the ARM request and in the run-command's own record.
        Remove-Variable -Name LabUserPasswordPlainText -ErrorAction SilentlyContinue
    }

    # DomainRole 4 = backup DC, 5 = primary DC. Same check promote-dc.ps1 uses.
    $role = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
    if ($role -lt 4) {
        throw "This machine is not a domain controller (DomainRole=$role). Run promote-dc.ps1 first and let the restart complete - a green deployment only means promotion was STAGED."
    }

    $isElevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isElevated) {
        throw 'Not running elevated. auditpol and the directory writes both need it. (Under az vm run-command this runs as SYSTEM and is already elevated.)'
    }

    # -IncludeManagementTools in promote-ad.ps1's Install-WindowsFeature is what
    # puts this module on the box. If it is missing, promotion was done some
    # other way and the RSAT AD PowerShell feature needs installing.
    Import-Module ActiveDirectory

    $domain = Get-ADDomain
    $script:DnsRoot = $domain.DNSRoot
    if (-not $DomainDistinguishedName) {
        $DomainDistinguishedName = $domain.DistinguishedName
    }

    Write-Step "Domain: $($domain.DNSRoot) (NetBIOS $($domain.NetBIOSName))"
    Write-Step "Naming context: $DomainDistinguishedName"
    Write-Step "Running as: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"

    # ------------------------------------------------------------------
    # 1. OU structure.
    # ------------------------------------------------------------------
    # The people OU is called Employees, NOT Users, and that is a hard constraint
    # rather than a naming preference. Every domain ships a built-in CN=Users
    # container, and Active Directory enforces uniqueness of the `name` attribute
    # among siblings REGARDLESS of the RDN prefix, so OU=Users next to CN=Users
    # fails with "An attempt was made to add an object to the directory with a
    # name that is already in use". Learned by hitting it on a live DC on
    # 2026-09-03. The reason a separate OU is wanted at all still stands:
    # CN=Users is a container, not an organizational unit, so Group Policy
    # cannot be linked to it and delegation against it is awkward.
    #
    # Workstations and Servers are empty at this point. They exist so that a
    # machine joining the domain later has somewhere correct to land, and so
    # that the 4741 (computer account created) events a join produces are
    # attributable to a deliberate structure.
    Write-Step '--- Section 1: organizational units ---'

    New-LabOu -Name 'Workstations'    -ParentPath $DomainDistinguishedName -Description 'Domain-joined client machines.'
    New-LabOu -Name 'Servers'         -ParentPath $DomainDistinguishedName -Description 'Domain-joined member servers.'
    New-LabOu -Name 'ServiceAccounts' -ParentPath $DomainDistinguishedName -Description 'Non-human accounts. Anything with an SPN lives here.'
    New-LabOu -Name 'Employees'       -ParentPath $DomainDistinguishedName -Description 'People. Parent of the per-department OUs. Not named Users: CN=Users already exists.'

    # An OU's DN is deterministic (OU=<Name>,<parent>) and New-LabOu has already
    # guaranteed the object exists or thrown, so the paths are composed here
    # rather than returned from the helper. See the note above the helpers for
    # why the helpers return nothing.
    $ouServiceAccts = "OU=ServiceAccounts,$DomainDistinguishedName"
    $ouUsers        = "OU=Employees,$DomainDistinguishedName"

    New-LabOu -Name 'IT'      -ParentPath $ouUsers -Description 'IT department users and the IT security group.'
    New-LabOu -Name 'Finance' -ParentPath $ouUsers -Description 'Finance department users and the Finance security group.'

    $ouIT      = "OU=IT,$ouUsers"
    $ouFinance = "OU=Finance,$ouUsers"

    # ------------------------------------------------------------------
    # 2. Users.
    # ------------------------------------------------------------------
    # Seven accounts: five people across two departments, two service accounts.
    # Every one of them is enabled, because a disabled account produces 4625 with
    # status 0xC0000072 and nothing else, which is not the telemetry this lab is
    # after.
    #
    # THE PRIVILEGE-ESCALATION TARGET is m.okafor. She is the only account added
    # to Domain Admins in Section 3, which makes her the obvious objective of any
    # escalation chain run in this lab and the only account whose logons will
    # carry 4672. Everything else here is a stepping stone toward that account.
    #
    # Emits per account: 4720 (created), 4722 (enabled), 4724 (password set).
    Write-Step '--- Section 2: users ---'

    New-LabUser -Sam 'j.reyes'  -DisplayName 'Jordan Reyes'  -GivenName 'Jordan' -Surname 'Reyes'  -Title 'Helpdesk Technician'  -Department 'IT'      -OuPath $ouIT      -Password $LabUserPassword -Description 'Tier 1 support. Unprivileged baseline for logon telemetry.'
    New-LabUser -Sam 'm.okafor' -DisplayName 'Maya Okafor'   -GivenName 'Maya'   -Surname 'Okafor' -Title 'Systems Administrator' -Department 'IT'     -OuPath $ouIT      -Password $LabUserPassword -Description 'PRIVILEGE-ESCALATION TARGET. Domain Admin. Her logons carry 4672.'
    New-LabUser -Sam 'a.chen'   -DisplayName 'Alex Chen'     -GivenName 'Alex'   -Surname 'Chen'   -Title 'Financial Analyst'    -Department 'Finance' -OuPath $ouFinance -Password $LabUserPassword -Description 'Unprivileged. Password-spray target surface.'
    New-LabUser -Sam 'p.novak'  -DisplayName 'Petra Novak'   -GivenName 'Petra'  -Surname 'Novak'  -Title 'Accounts Payable Clerk' -Department 'Finance' -OuPath $ouFinance -Password $LabUserPassword -Description 'Unprivileged. Password-spray target surface.'
    New-LabUser -Sam 't.walsh'  -DisplayName 'Tomas Walsh'   -GivenName 'Tomas'  -Surname 'Walsh'  -Title 'Controller'           -Department 'Finance' -OuPath $ouFinance -Password $LabUserPassword -Description 'Unprivileged but high-value data access. Realistic phishing target.'

    # Service accounts. Both live in OU=ServiceAccounts so that "non-human" is a
    # structural fact about the directory rather than a naming convention that
    # only holds while everyone remembers it.
    New-LabUser -Sam 'svc-backup'    -DisplayName 'svc-backup'    -GivenName 'Service' -Surname 'Backup' -Title 'Backup Service'   -Department 'IT' -OuPath $ouServiceAccts -Password $LabUserPassword -Description 'Service account, no SPN. Member of IT-Admins: over-privileged on purpose.'
    New-LabUser -Sam 'svc-sqlreport' -DisplayName 'svc-sqlreport' -GivenName 'Service' -Surname 'SQLReport' -Title 'SQL Reporting Service' -Department 'IT' -OuPath $ouServiceAccts -Password $LabUserPassword -Description 'SPN-BEARING. The Kerberoastable account (T1558.003). See Section 4.'

    # ------------------------------------------------------------------
    # 3. Groups and membership.
    # ------------------------------------------------------------------
    # Emits 4727 per group created and 4728 per member added.
    #
    # The Domain Admins addition is the point of this section. Without at least
    # one non-built-in account in Domain Admins, every logon on this DC is
    # either the built-in Administrator or an ordinary user, and "privileged
    # logon" is not a category the telemetry can express. With it, 4672
    # separates one account's logons from the other six, and a detection can
    # actually key on the distinction.
    Write-Step '--- Section 3: groups and membership ---'

    New-LabGroup -Name 'IT-Admins'       -OuPath $ouIT      -Description 'Local administrators on member servers and workstations.'
    New-LabGroup -Name 'Finance-ReadOnly' -OuPath $ouFinance -Description 'Read access to finance file shares.'

    Add-LabGroupMember -GroupIdentity 'IT-Admins' -MemberSam 'j.reyes'
    Add-LabGroupMember -GroupIdentity 'IT-Admins' -MemberSam 'm.okafor'
    Add-LabGroupMember -GroupIdentity 'IT-Admins' -MemberSam 'svc-backup'

    # svc-sqlreport is in IT-Admins deliberately, and this is the whole escalation
    # chain in one line: the SPN-bearing account (Section 4) is Kerberoastable,
    # and cracking it yields IT-Admins rather than nothing. That is what makes a
    # 4769 against this account worth alerting on instead of being noise. It is
    # also exactly the misconfiguration every real AD assessment finds.
    Add-LabGroupMember -GroupIdentity 'IT-Admins' -MemberSam 'svc-sqlreport'

    Add-LabGroupMember -GroupIdentity 'Finance-ReadOnly' -MemberSam 'a.chen'
    Add-LabGroupMember -GroupIdentity 'Finance-ReadOnly' -MemberSam 'p.novak'
    Add-LabGroupMember -GroupIdentity 'Finance-ReadOnly' -MemberSam 't.walsh'

    # Domain Admins is a built-in GLOBAL group, so this emits 4728 (not 4732).
    Add-LabGroupMember -GroupIdentity 'Domain Admins' -MemberSam 'm.okafor'

    # ------------------------------------------------------------------
    # 4. The SPN. THIS IS THE SECTION THAT MATTERS.
    # ------------------------------------------------------------------
    # Registering a Service Principal Name on a normal USER account is what makes
    # Kerberoasting (MITRE T1558.003) possible, and therefore what makes it
    # detectable. The mechanics, because the detection depends on them:
    #
    #   - Any authenticated domain user can enumerate SPNs from the directory
    #     (`setspn -T lab.dlpz.local -Q */*`, GetUserSPNs.py, Rubeus kerberoast).
    #     No special rights are needed. Enumeration is a directory read and is
    #     largely invisible.
    #   - Any authenticated domain user can then request a service ticket for
    #     that SPN. The DC issues it, encrypted with a key derived from the
    #     SERVICE ACCOUNT'S PASSWORD, and logs 4769.
    #   - The attacker takes the ticket offline and cracks it. Nothing about the
    #     cracking touches the network, which is why 4769 - the request - is the
    #     only reliable signal, and why this SPN is the object a T1558.003 rule
    #     needs to exist at all.
    #   - SPNs on COMPUTER accounts are not interesting: the password is machine
    #     generated, 120 characters, and rotates. SPNs on USER accounts are the
    #     finding. That is why svc-sqlreport is a user object.
    #
    # configs/coverage_config.yml lists T1558.003 under `critical` and no rule in
    # rules/ covers it. This object is the prerequisite for closing that gap.
    #
    # HONEST LIMIT ON THE CRACK, not on the detection: this account gets the same
    # strong lab password as everyone else, so a real crack attempt against it
    # will fail. That is fine and intentional. The lab is measuring whether the
    # DC emits and Sentinel ingests the 4769 REQUEST, not whether an offline
    # crack succeeds. If you want the crack to succeed for a demo, set a weak
    # password on this one account by hand and say so in the writeup.
    #
    # SECOND HONEST LIMIT, on ticket encryption type: the classic Kerberoast
    # detection keys on TicketEncryptionType 0x17 (RC4), because attackers
    # request RC4 to get a faster-cracking hash. Whether this DC will actually
    # ISSUE an RC4 ticket depends on the account's msDS-SupportedEncryptionTypes
    # and on the DC's Kerberos hardening state, both of which Microsoft has been
    # tightening. Check both on the live DC before writing a rule that keys on
    # 0x17:
    #   Get-ADUser svc-sqlreport -Properties msDS-SupportedEncryptionTypes
    # The 4769 event itself fires regardless of encryption type.
    #
    # Emits 4738 (user account changed) when the SPN is written.
    Write-Step '--- Section 4: service principal name (the Kerberoasting target) ---'

    $spn = '{0}.{1}:{2}' -f $ServiceAccountSpnPrefix, $script:DnsRoot, $ServiceAccountSpnPort
    $svc = Get-ADUser -Identity 'svc-sqlreport' -Properties ServicePrincipalNames

    if ($svc.ServicePrincipalNames -contains $spn) {
        Write-Step "SPN $spn on svc-sqlreport" 'skip'
    }
    else {
        # Set-ADUser with @{Add=...} rather than setspn.exe: it is the same write
        # to the same attribute, but it fails loudly on a duplicate SPN instead
        # of prompting, and it does not depend on setspn.exe being present.
        # `setspn -L svc-sqlreport` reads back exactly what this writes.
        Set-ADUser -Identity 'svc-sqlreport' -ServicePrincipalNames @{ Add = $spn }
        Write-Step "SPN $spn on svc-sqlreport" 'new'
    }

    # ------------------------------------------------------------------
    # 5. Advanced audit policy.
    # ------------------------------------------------------------------
    # A promoted DC does not emit most of what this lab needs by default. This
    # section turns on the specific subcategories that produce the event IDs the
    # corpus consumes today plus the ones an AD detection will consume next, and
    # nothing else. The same discipline the DCR applies to ingestion, applied to
    # emission.
    #
    # THE GOTCHA THAT WILL BITE YOU: auditpol writes the LOCAL effective policy,
    # and Group Policy overwrites local audit policy at the next refresh when a
    # linked GPO defines audit settings. The Default Domain Controllers Policy
    # in a new forest does define the legacy audit categories, and legacy
    # category settings are expanded into their subcategories when applied. So a
    # `gpupdate /force` can silently revert some of what this section sets. The
    # check, not a guess:
    #   gpupdate /force ; auditpol /get /category:"Account Logon","Logon/Logoff"
    # If it has reverted, either re-run this script (it is idempotent) or move
    # these settings into the Default Domain Controllers Policy under
    # Advanced Audit Policy Configuration, which is the durable fix. For a burst
    # lab that gets deleted in days, re-running is the cheaper answer.
    #
    # Subcategory -> event ID mapping, which is the only reason this table is a
    # table and not four auditpol lines:
    #
    #   Logon                            -> 4624 success, 4625 failure, 4648
    #                                       explicit-credential logon.
    #                                       4625 is what feeds BOTH credential-access
    #                                       correlations in rules/; 4624 is the
    #                                       investigation context the brute-force
    #                                       rule asks the analyst to confirm.
    #   Logoff                           -> 4634, 4647. Session duration. Failure
    #                                       auditing is not offered for logoff.
    #   Special Logon                    -> 4672. THE PRIVILEGED MARKER. This is
    #                                       what makes m.okafor's Domain Admins
    #                                       membership visible in telemetry.
    #                                       Note dcr.bicep deliberately does NOT
    #                                       collect 4672 today - it is emitted
    #                                       here, ingesting it is a separate
    #                                       spending decision.
    #   Account Lockout                  -> 4625 with status 0xC0000234, the
    #                                       lockout-specific failure. Separating
    #                                       "locked out" from "wrong password"
    #                                       is what stops a brute-force rule
    #                                       double-counting the tail of an attack.
    #   Kerberos Authentication Service  -> 4768 TGT issued, 4771 pre-auth failed,
    #                                       4772 TGT request failed. 4771 is the
    #                                       domain-account analogue of 4625 and is
    #                                       often the earlier signal of a spray.
    #   Kerberos Service Ticket Ops      -> 4769 service ticket requested, 4770
    #                                       renewed, 4773 request failed.
    #                                       4769 IS THE KERBEROASTING EVENT.
    #                                       Without this subcategory, Section 4's
    #                                       SPN produces an attackable object and
    #                                       no evidence that it was attacked.
    #   User Account Management          -> 4720 created, 4722 enabled, 4723/4724
    #                                       password change/reset, 4725 disabled,
    #                                       4726 deleted, 4738 changed, 4740
    #                                       locked out, 4767 unlocked.
    #                                       Persistence and account-manipulation
    #                                       coverage, and the events this script's
    #                                       own Sections 2 and 4 generate.
    #   Security Group Management        -> 4727 group created, 4728 member added
    #                                       to a global group, 4729 removed, 4731
    #                                       /4732/4733 the domain-local forms,
    #                                       4735 changed. A 4728 naming Domain
    #                                       Admins is one of the highest-signal
    #                                       events in a Windows estate.
    #   Computer Account Management      -> 4741 created, 4742 changed, 4743
    #                                       deleted. Nothing emits these yet; the
    #                                       Workstations and Servers OUs exist so
    #                                       that when a machine joins, it does.
    #   Directory Service Access         -> 4662. GOTCHA: 4662 is SACL-gated, not
    #                                       policy-gated. Enabling this
    #                                       subcategory does not by itself produce
    #                                       events for an object whose SACL does
    #                                       not audit the operation. If you need
    #                                       4662 on a specific object (a DCSync
    #                                       detection keying on the
    #                                       DS-Replication-Get-Changes-All extended
    #                                       right is the usual reason), add the
    #                                       audit ACE to that object's SACL
    #                                       yourself. This script does not modify
    #                                       any SACL.
    #
    # Deliberately NOT enabled, and why - same reasoning as the DCR's
    # "deliberately NOT collected" list:
    #   Credential Validation (4776/4777) - NTLM validation, very high volume on a
    #     DC, and no rule in rules/ consumes it. Add it with the rule that needs it.
    #   Directory Service Changes (5136/5137/5139/5141) - richer than 4662 because
    #     it carries old and new attribute values, but equally SACL-gated and
    #     materially more voluminous. Worth enabling for a specific AD-persistence
    #     hunt, not as a default.
    #   Object Access / File System / Registry - nothing in the corpus consumes
    #     them and they are the classic way to fill a 1 GB/day cap by lunchtime.
    Write-Step '--- Section 5: advanced audit policy ---'

    if ($SkipAuditPolicy) {
        Write-Step 'Skipped by -SkipAuditPolicy. The DC will emit only what its current policy already allows.'
    }
    else {
        # GUIDs are the locale-independent fallback path only; see
        # Set-LabAuditSubcategory. Verify with `auditpol /list /subcategory:* /v`
        # if the English-name path ever fails on a non-en-US image.
        $auditSubcategories = @(
            @{ Name = 'Logon';                              Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true  }
            @{ Name = 'Logoff';                             Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $false }
            @{ Name = 'Special Logon';                      Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $false }
            @{ Name = 'Account Lockout';                    Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true  }
            @{ Name = 'Kerberos Authentication Service';    Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true  }
            @{ Name = 'Kerberos Service Ticket Operations'; Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true  }
            @{ Name = 'User Account Management';            Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true  }
            @{ Name = 'Security Group Management';          Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true  }
            @{ Name = 'Computer Account Management';        Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true  }
            @{ Name = 'Directory Service Access';           Guid = '{0CCE923B-69AE-11D9-BED3-505054503030}'; Success = $true; Failure = $true  }
        )

        foreach ($sub in $auditSubcategories) {
            Set-LabAuditSubcategory -Name $sub.Name -Guid $sub.Guid -Success $sub.Success -Failure $sub.Failure
        }
    }

    # ------------------------------------------------------------------
    # 6. Verification summary. Screenshot this.
    # ------------------------------------------------------------------
    # Kept compact on purpose: Azure truncates run-command output, and a summary
    # that gets cut off is not evidence. The full transcript is on the DC at
    # C:\Windows\Temp\seed-ad.log.
    #
    # Everything below is a READ BACK from the directory and from auditpol, not
    # an echo of what the script intended to do. A section that silently failed
    # shows up here as a missing row.
    Write-Output ''
    Write-Output '=============================================================='
    Write-Output " SEED VERIFICATION  -  $($domain.DNSRoot)  -  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ssZ')"
    Write-Output '=============================================================='

    $labOuNames = 'Workstations', 'Servers', 'ServiceAccounts', 'Employees', 'IT', 'Finance'
    # -Properties ProtectedFromAccidentalDeletion is REQUIRED here and its absence
    # was a real bug. That property is CONSTRUCTED - the AD module derives it from
    # the object's ACL rather than reading a stored attribute - so it is not in
    # this cmdlet's default property set. Omit the request and it comes back
    # $null, which is falsy, and a bare truth test then prints UNPROTECTED for an
    # OU that is in fact protected. That is what happened on the 2026-09-03 run:
    # New-LabOu passes -ProtectedFromAccidentalDeletion $true and did not error,
    # yet every OU reported UNPROTECTED, and that false reading was carried into
    # docs/AD_LAB_EVIDENCE.md as a finding about the directory. It was a finding
    # about this read-back.
    $foundOus = Get-ADOrganizationalUnit -Filter * -SearchBase $DomainDistinguishedName `
        -Properties ProtectedFromAccidentalDeletion |
        Where-Object { $labOuNames -contains $_.Name }
    Write-Output ("OUs (lab)          : {0} of {1} present" -f @($foundOus).Count, $labOuNames.Count)
    foreach ($ou in ($foundOus | Sort-Object DistinguishedName)) {
        # $null is reported as UNKNOWN rather than folded into $false, so a future
        # property-set change surfaces as a read-back failure instead of a silent
        # wrong answer. Same rule the auditpol block below follows with UNREADABLE:
        # "could not read it" and "it is off" are different sentences.
        $protected = $ou.ProtectedFromAccidentalDeletion
        $protection = if ($null -eq $protected) { 'UNKNOWN (property not returned)' }
                      elseif ($protected)       { 'protected' }
                      else                      { 'UNPROTECTED' }
        Write-Output ("                     {0}  [{1}]" -f $ou.DistinguishedName, $protection)
    }

    $labUsers = Get-ADUser -Filter * -SearchBase $DomainDistinguishedName -Properties Enabled, Department |
        Where-Object { $_.DistinguishedName -like "*OU=Employees,$DomainDistinguishedName" -or
                       $_.DistinguishedName -like "*OU=ServiceAccounts,$DomainDistinguishedName" }
    $enabledCount = @($labUsers | Where-Object { $_.Enabled }).Count
    Write-Output ''
    Write-Output ("Users (lab OUs)    : {0} total, {1} enabled" -f @($labUsers).Count, $enabledCount)
    foreach ($u in ($labUsers | Sort-Object SamAccountName)) {
        Write-Output ("                     {0,-16} {1,-9} {2}" -f $u.SamAccountName, $u.Department, $u.DistinguishedName)
    }

    Write-Output ''
    foreach ($groupName in 'IT-Admins', 'Finance-ReadOnly', 'Domain Admins') {
        $g = Get-ADGroup -Filter "SamAccountName -eq '$groupName'"
        if (-not $g) {
            Write-Output ("Group {0,-18}: MISSING" -f $groupName)
            continue
        }
        $members = (Get-ADGroupMember -Identity $g | Sort-Object SamAccountName | Select-Object -ExpandProperty SamAccountName) -join ', '
        Write-Output ("Group {0,-18}: {1}" -f $groupName, $members)
    }

    # The SPN read-back. This is the line that proves the Kerberoasting target
    # exists, so it is printed on its own and named as such.
    Write-Output ''
    $svcCheck = Get-ADUser -Identity 'svc-sqlreport' -Properties ServicePrincipalNames, 'msDS-SupportedEncryptionTypes'
    $spnList = @($svcCheck.ServicePrincipalNames)
    if ($spnList.Count -gt 0) {
        Write-Output ("SPN (T1558.003)    : {0}" -f ($spnList -join ', '))
        Write-Output ("  on account       : {0} ({1})" -f $svcCheck.SamAccountName, $svcCheck.DistinguishedName)
        $etypes = $svcCheck.'msDS-SupportedEncryptionTypes'
        $etypeText = if ($null -eq $etypes) { 'not set (DC default applies)' } else { $etypes }
        Write-Output ("  msDS-SupportedEncryptionTypes: {0}" -f $etypeText)
        Write-Output ('  Attacker view    : setspn -T {0} -Q */*' -f $domain.DNSRoot)
    }
    else {
        Write-Output 'SPN (T1558.003)    : MISSING - Kerberoasting is NOT testable in this domain.'
    }

    Write-Output ''
    Write-Output 'Effective audit policy (read back from auditpol, not from this script):'
    $verifySubs = 'Logon', 'Logoff', 'Special Logon', 'Account Lockout',
                  'Kerberos Authentication Service', 'Kerberos Service Ticket Operations',
                  'User Account Management', 'Security Group Management',
                  'Computer Account Management', 'Directory Service Access'
    foreach ($name in $verifySubs) {
        # /r emits CSV with a header row. Blank lines have to be dropped before
        # ConvertFrom-Csv or it consumes one as the header.
        #
        # The setting column is selected by MATCHING the header rather than by
        # hardcoding "Inclusion Setting", with a positional fallback. Two reasons,
        # and neither is defensiveness for its own sake: the CSV header is
        # localised the same way the subcategory names are, and auditpol /get
        # needs SeSecurityPrivilege, so a non-elevated run gets exit 1314
        # (ERROR_PRIVILEGE_NOT_HELD) and no rows at all. UNREADABLE below means
        # the read-back failed, NOT that auditing is off.
        $rows = auditpol /get /subcategory:"$name" /r 2>$null | Where-Object { $_.Trim() } | ConvertFrom-Csv
        $row = $rows | Select-Object -First 1
        if ($row) {
            $props = @($row.PSObject.Properties)
            $col = $props | Where-Object { $_.Name -like '*Inclusion*' } | Select-Object -First 1
            if (-not $col -and $props.Count -ge 5) { $col = $props[4] }
            $setting = if ($col) { $col.Value } else { 'UNPARSEABLE' }
        }
        else {
            $setting = 'UNREADABLE'
        }
        Write-Output ("  {0,-36} {1}" -f $name, $setting)
    }

    Write-Output ''
    Write-Output ("Run result         : {0} created, {1} already existed, {2} failed" -f $script:Created, $script:Existing, $script:Failed)
    Write-Output "Transcript         : $transcript"
    Write-Output '=============================================================='
    Write-Output ''
    Write-Output 'Reminder: the DC now EMITS 4768/4769/4672. dcr.bicep does not INGEST them.'
    Write-Output 'Widening the DCR XPath is a spending decision - make it with the rule that needs it.'

    if ($script:Failed -gt 0) {
        # Exit non-zero so a partial seed is not reported as a green run. The
        # summary above already names which rows are missing.
        Stop-Transcript | Out-Null
        exit 1
    }

    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Step "FAILED: $($_.Exception.Message)" 'fail'
    Write-Step "Transcript: $transcript"
    Stop-Transcript | Out-Null
    exit 1
}
