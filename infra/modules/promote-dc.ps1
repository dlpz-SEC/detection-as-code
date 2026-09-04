<#
    Promote the lab VM to an Active Directory domain controller.

    Runs once, via the CustomScriptExtension declared in vm.bicep, when
    promoteToDomainController = true. It is embedded into that extension as
    base64 (the same pattern sysmonconfig.xml uses) rather than downloaded, so
    the VM needs no external script host and the promotion is version-controlled
    alongside the template that runs it.

    WHY A DATA DISK. AD DS puts its database (NTDS.dit), its transaction logs
    and SYSVOL on this disk deliberately, and vm.bicep attaches it with
    caching: 'None'. Host write-back caching in front of a directory database
    risks a USN rollback if the host loses the write - the failure mode that
    leaves a DC silently serving stale objects. Microsoft's guidance for AD DS
    on Azure is an uncached data disk, never the OS disk. This script formats
    that disk and points all three paths at it.

    WHY -NoRebootOnCompletion. Promotion always requires a reboot, and a reboot
    kills the CustomScriptExtension mid-run, which Azure then reports as a
    failed extension even though the promotion succeeded. So the promotion is
    told not to reboot itself; the script schedules the restart AFTER it exits
    cleanly, and the extension reports success. The domain is not usable until
    that restart completes (roughly two to four minutes).

    DNS. Install-ADDSForest installs and configures the DNS Server role
    (-InstallDns). vm.bicep has already pointed the NIC at this VM's own static
    private IP as primary resolver, with Azure's platform resolver
    (168.63.129.16) as secondary so that the AMA and Sysmon extensions can still
    resolve public names during the window before this script runs. That
    secondary is a deliberate lab compromise: on a production DC you would list
    only domain controllers and let a forwarder handle external names.

    SCOPE. This promotes a NEW forest with a single domain controller. It is not
    a replica promotion and does not join an existing forest.

    CREDENTIAL HANDLING. -DsrmPassword arrives from the extension's
    protectedSettings, which Azure encrypts at rest and never returns from a GET
    on the extension. It is not written to disk by this script and is not
    echoed. It is still a lab credential in a non-routable domain - treat it as
    disposable and never reuse a real password here.

    IDEMPOTENCE. Safe to re-run. If the machine is already a domain controller
    the script reports that and exits 0 rather than failing the extension.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $DomainName,

    [Parameter(Mandatory = $true)]
    [string] $NetbiosName,

    [Parameter(Mandatory = $true)]
    [string] $DsrmPassword,

    # Minutes to wait before the post-promotion restart. The default gives the
    # extension time to report success to Azure before the machine drops.
    [int] $RestartDelaySeconds = 60
)

$ErrorActionPreference = 'Stop'
$transcript = 'C:\Windows\Temp\promote-dc.log'
Start-Transcript -Path $transcript -Append | Out-Null

function Write-Step { param([string] $Message) Write-Output "[promote-dc] $Message" }

try {
    # ------------------------------------------------------------------
    # 0. Already a DC? Then this is a re-run. Report and leave.
    # ------------------------------------------------------------------
    # DomainRole 4 = backup DC, 5 = primary DC. Anything less is not promoted.
    $role = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
    if ($role -ge 4) {
        Write-Step "Already a domain controller (DomainRole=$role). Nothing to do."
        Stop-Transcript | Out-Null
        exit 0
    }

    # ------------------------------------------------------------------
    # 1. Prepare the AD DS data disk.
    # ------------------------------------------------------------------
    # vm.bicep attaches exactly one empty uncached data disk at LUN 0. It
    # arrives RAW. Anything already partitioned is left alone so a re-run does
    # not touch existing data.
    Write-Step 'Looking for the raw AD DS data disk.'
    $raw = Get-Disk | Where-Object { $_.PartitionStyle -eq 'RAW' } | Sort-Object Number | Select-Object -First 1

    if ($null -ne $raw) {
        Write-Step "Initializing disk $($raw.Number) ($([math]::Round($raw.Size / 1GB)) GB)."
        $volume = $raw |
            Initialize-Disk -PartitionStyle GPT -PassThru |
            New-Partition -AssignDriveLetter -UseMaximumSize |
            Format-Volume -FileSystem NTFS -NewFileSystemLabel 'ADDS' -Confirm:$false
        $driveLetter = $volume.DriveLetter
    }
    else {
        # Re-run, or the disk was formatted by hand. Find it by label.
        Write-Step 'No raw disk found; looking for an existing ADDS volume.'
        $volume = Get-Volume | Where-Object { $_.FileSystemLabel -eq 'ADDS' } | Select-Object -First 1
        if ($null -eq $volume) {
            throw 'No raw data disk and no volume labelled ADDS. Expected an empty data disk at LUN 0 - check that promoteToDomainController was true at deploy time.'
        }
        $driveLetter = $volume.DriveLetter
    }

    if ([string]::IsNullOrWhiteSpace($driveLetter)) {
        throw 'The AD DS data disk has no drive letter. Cannot place NTDS/SYSVOL.'
    }

    $dbPath     = "${driveLetter}:\NTDS"
    $logPath    = "${driveLetter}:\NTDS"
    $sysvolPath = "${driveLetter}:\SYSVOL"
    Write-Step "AD DS paths: database=$dbPath sysvol=$sysvolPath"

    # ------------------------------------------------------------------
    # 2. Install the role.
    # ------------------------------------------------------------------
    Write-Step 'Installing the AD-Domain-Services role and management tools.'
    # -IncludeManagementTools brings the ActiveDirectory PowerShell module, which
    # seed-ad.ps1 needs immediately after the reboot. Without it, New-ADUser and
    # New-ADOrganizationalUnit are not available.
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null

    # ------------------------------------------------------------------
    # 3. Promote to a new forest.
    # ------------------------------------------------------------------
    Import-Module ADDSDeployment

    $dsrm = ConvertTo-SecureString -String $DsrmPassword -AsPlainText -Force

    Write-Step "Promoting to a new forest: $DomainName (NetBIOS $NetbiosName)."
    # -InstallDns:$true is what makes this VM its own resolver, which is why
    # vm.bicep lists its private IP first in the NIC's dnsServers.
    # ForestMode/DomainMode WinThreshold = 2016 functional level, the highest
    # level Server 2022 offers and the right default for a greenfield lab.
    Install-ADDSForest `
        -DomainName $DomainName `
        -DomainNetbiosName $NetbiosName `
        -SafeModeAdministratorPassword $dsrm `
        -DatabasePath $dbPath `
        -LogPath $logPath `
        -SysvolPath $sysvolPath `
        -InstallDns:$true `
        -ForestMode 'WinThreshold' `
        -DomainMode 'WinThreshold' `
        -NoRebootOnCompletion:$true `
        -Force:$true | Out-Null

    Write-Step 'Promotion staged. Scheduling the restart that completes it.'

    # ------------------------------------------------------------------
    # 4. Restart on a delay, so the extension reports success first.
    # ------------------------------------------------------------------
    Start-Process -FilePath 'shutdown.exe' `
        -ArgumentList "/r /t $RestartDelaySeconds /c ""AD DS promotion: completing"" /d p:2:4" `
        -NoNewWindow

    Write-Step "Restart scheduled in $RestartDelaySeconds seconds. The domain is usable once it comes back (about 2-4 minutes)."
    Write-Step "Next step: run infra/scripts/seed-ad.ps1 to create the OUs, users, groups and the SPN service account."
    Stop-Transcript | Out-Null
    exit 0
}
catch {
    Write-Step "FAILED: $($_.Exception.Message)"
    Write-Step "Transcript: $transcript"
    Stop-Transcript | Out-Null
    # Non-zero so the extension surfaces the failure rather than reporting a
    # green deploy over a VM that never became a domain controller.
    exit 1
}
