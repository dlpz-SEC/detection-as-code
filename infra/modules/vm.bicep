// Windows event source — the VM that makes the DCR do something (Phase 2).
//
// A stock Azure Windows VM sends NOTHING to the workspace on its own. Three
// things have to line up, and this module does all three:
//   1. Azure Monitor Agent (AMA)  — the shipper.
//   2. A Data Collection Rule ASSOCIATION — binds THIS VM to the existing
//      dcr-windows-security-events so AMA knows what to collect (Security
//      4624/4625 + Sysmon EID 1/10). Without the association the agent is idle.
//   3. Sysmon + a config — the EID 1/10 rules have no telemetry otherwise; a
//      stock VM has no Sysmon, and stock Sysmon does not emit EID 10 without an
//      explicit ProcessAccess rule (see sysmonconfig.xml).
//
// COST — this is where the meter starts. A running VM bills compute per second
// and its telemetry bills ingestion against the 1 GB/day cap. Mitigations wired
// in: a small burstable size default, an auto-shutdown schedule, and a Sysmon
// config narrowed to two event IDs. Teardown is still `az group delete`.
//
// EXPOSURE — RDP (3389) is the attack surface. The NSG rule is fail-closed:
// with no allowedRdpSourceIp supplied it locks the source to an unroutable
// address (nobody), never '*'. Supply your own public IP to get in.
//
// PHASE 2b — DOMAIN CONTROLLER. Setting promoteToDomainController = true turns
// this same VM into the lab's AD DS domain controller rather than adding a
// second machine. That changes four things (each commented at its site): an
// uncached data disk for NTDS/SYSVOL, a static private IP, a resolver pointed
// at itself, and a third extension running promote-dc.ps1.
//
// What it buys: the 4624/4625 the DCR already collects stop being local logons
// and become DOMAIN authentication, and the box starts emitting the Kerberos
// events (4768/4769/4771) that AD detections key on. Widening the DCR to
// collect them is a separate, deliberate spending decision - see dcr.bicep.
//
// What it costs beyond the VM: one more managed disk billed 24/7. Note that the
// OS disk and the static public IP already bill whether or not the VM is
// running, so `deallocate` trims the compute line and nothing else. Teardown is
// the only thing that stops the meter.

@description('Azure region. Should match the workspace/DCR region (westus).')
param location string

@description('VM name. computerName is derived from it (Windows caps that at 15 chars).')
param vmName string = 'sc200-win-vm'

@description('VM size. Standard_B2s (2 vCPU / 4 GB, burstable) is the cheap lab default; enough to run AMA + Sysmon + a benign attack sim.')
param vmSize string = 'Standard_B2s'

@description('Local administrator username.')
param adminUsername string

@description('Local administrator password. Supply at deploy time (az prompts, or a Key Vault reference) — never commit it.')
@secure()
param adminPassword string

@description('CIDR/IP allowed to reach RDP (3389). Fail-closed: empty locks RDP to an unroutable source. Set to YOUR public IP, e.g. 203.0.113.4/32.')
param allowedRdpSourceIp string = ''

@description('ARM resource ID of the existing DCR to associate this VM with.')
param dataCollectionRuleId string

@description('Official Sysinternals download for Sysmon. Pin only if you need reproducibility.')
param sysmonDownloadUrl string = 'https://download.sysinternals.com/files/Sysmon.zip'

@description('Local shutdown time (HHmm, 24h) for the auto-shutdown schedule.')
param autoShutdownTime string = '0100'

@description('Time zone ID for the auto-shutdown schedule.')
param autoShutdownTimeZone string = 'Pacific Standard Time'

@description('Tags applied to every resource.')
param tags object

// ---------------------------------------------------------------------------
// Domain controller mode (Phase 2b). Off by default.
// ---------------------------------------------------------------------------
// Promoting this VM rather than standing up a second one is deliberate: one VM
// is one compute bill, and a lone DC is also a perfectly good Sysmon event
// source. The trade is that the event source and the directory share a blast
// radius, which is the right trade for a burst lab and the wrong one anywhere
// real.
//
// What flipping this on changes: an uncached data disk is attached for
// NTDS/SYSVOL, the private IP goes static (a DC cannot float), the NIC points
// its resolver at itself, and a third extension runs promote-dc.ps1.

@description('Promote this VM to an Active Directory domain controller. STARTS THE AD DS PATH: attaches a data disk, pins the private IP, repoints DNS, and runs promote-dc.ps1. Requires dsrmPassword.')
param promoteToDomainController bool = false

@description('FQDN of the lab forest root domain. Non-routable by design. Used only when promoteToDomainController = true.')
param domainName string = 'lab.dlpz.local'

@description('NetBIOS name of the lab domain. Windows caps this at 15 characters and upper-cases it.')
@maxLength(15)
param domainNetbiosName string = 'LAB'

@description('Directory Services Restore Mode password. Required when promoteToDomainController = true; supply at deploy time and never commit it. Travels in the extension protectedSettings, which Azure encrypts and does not return on GET.')
@secure()
param dsrmPassword string = ''

@description('Static private IP for the domain controller. Must sit inside the subnet prefix below; Azure reserves the first four addresses of any subnet, so .4 is the first assignable.')
param dcPrivateIp string = '10.20.0.4'

@description('Size of the AD DS data disk holding NTDS.dit, its logs and SYSVOL. 32 GB is far more than a lab directory needs; the floor is set by the disk tier, not the data.')
@minValue(4)
param dcDataDiskSizeGb int = 32

var computerName = take(replace(vmName, '-', ''), 15)

// Fail-closed RDP source: never fall back to '*'. An unroutable /32 = nobody.
var rdpSource = empty(allowedRdpSourceIp) ? '255.255.255.255/32' : allowedRdpSourceIp

// Sysmon install runs entirely inline (no external script host): the config is
// embedded as base64 from sysmonconfig.xml, and every PowerShell string literal
// is single-quoted so nothing collides with the outer -Command "..." quotes.
var sysmonConfigB64 = base64(loadTextContent('sysmonconfig.xml'))
var sysmonCommand = 'powershell -ExecutionPolicy Unrestricted -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; [IO.File]::WriteAllBytes(\'C:\\Windows\\Temp\\sysmonconfig.xml\',[Convert]::FromBase64String(\'${sysmonConfigB64}\')); Invoke-WebRequest -Uri \'${sysmonDownloadUrl}\' -OutFile \'C:\\Windows\\Temp\\Sysmon.zip\' -UseBasicParsing; Expand-Archive -Path \'C:\\Windows\\Temp\\Sysmon.zip\' -DestinationPath \'C:\\Windows\\Temp\\Sysmon\' -Force; & \'C:\\Windows\\Temp\\Sysmon\\Sysmon64.exe\' -accepteula -i \'C:\\Windows\\Temp\\sysmonconfig.xml\'"'

// AD DS promotion script, loaded from disk at compile time so the promotion
// travels with the template and the VM downloads nothing.
//
// It is delivered as a MANAGED RUN COMMAND, not a second CustomScriptExtension.
// That is not a style preference, it is a hard Azure constraint learned the
// expensive way: a Windows VM permits only ONE extension per handler, and
// InstallSysmon already occupies Microsoft.Compute.CustomScriptExtension. A
// second one fails at provisioning time with
//   "Multiple VMExtensions per handler not supported for OS type 'Windows'"
// and `what-if` does NOT catch it, because the rule is enforced when the
// resource is provisioned rather than when the template is validated.
//
// Microsoft.Compute/virtualMachines/runCommands is a distinct resource type
// rather than an extension of that handler, so it coexists with Sysmon. It also
// takes the DSRM password as a protectedParameter, which is strictly better
// than interpolating it into a command string: `source.script` is readable on a
// GET, protectedParameters are not.
var addsScript = loadTextContent('promote-dc.ps1')

// Resolver order for DC mode. Itself first, because a domain controller must
// resolve its own SRV records; Azure's platform resolver second, because the
// AMA and Sysmon extensions run BEFORE promotion and would otherwise have no
// working DNS at all. Before promotion the primary refuses the connection
// immediately and Windows fails over, so the cost is negligible.
//
// On a production DC you would list only domain controllers here and put the
// public side behind a forwarder. This is a single-DC lab with no members, so
// the compromise buys working extensions for no practical risk.
var dcDnsServers = [
  dcPrivateIp
  '168.63.129.16'
]

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${vmName}-nsg'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'Allow-RDP-From-Admin'
        properties: {
          priority: 1000
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: rdpSource
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: '${vmName}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [ '10.20.0.0/24' ]
    }
    subnets: [
      {
        name: 'default'
        properties: {
          addressPrefix: '10.20.0.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2023-09-01' = {
  name: '${vmName}-pip'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2023-09-01' = {
  name: '${vmName}-nic'
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: vnet.properties.subnets[0].id
          }
          // A domain controller cannot float: its address is baked into the
          // SRV records it registers and into every member's resolver config.
          // Plain event-source mode keeps the dynamic lease.
          privateIPAllocationMethod: promoteToDomainController ? 'Static' : 'Dynamic'
          privateIPAddress: promoteToDomainController ? dcPrivateIp : null
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
    // Only overridden in DC mode. Left unset otherwise so the VM keeps Azure's
    // default resolver.
    dnsSettings: promoteToDomainController ? {
      dnsServers: dcDnsServers
    } : null
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: vmName
  location: location
  tags: tags
  identity: {
    // System-assigned identity: AMA's recommended posture on Azure VMs.
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: computerName
      adminUsername: adminUsername
      adminPassword: adminPassword
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter-azure-edition'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
      // AD DS data disk. Empty in event-source mode.
      //
      // caching: 'None' is not a tuning choice, it is a correctness one. Host
      // write-back caching in front of a directory database can lose an
      // acknowledged write on host failure, which is the classic route to a USN
      // rollback: the DC keeps serving objects the rest of the forest has moved
      // past, silently. Microsoft's AD-DS-on-Azure guidance is an uncached data
      // disk for NTDS/SYSVOL, never the OS disk. promote-dc.ps1 formats this and
      // points DatabasePath/LogPath/SysvolPath at it.
      dataDisks: promoteToDomainController ? [
        {
          lun: 0
          createOption: 'Empty'
          diskSizeGB: dcDataDiskSizeGb
          caching: 'None'
          managedDisk: {
            storageAccountType: 'StandardSSD_LRS'
          }
        }
      ] : []
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
  }
}

// Auto-shutdown to cap idle spend. Deallocates the VM nightly; you still pay for
// the disk and public IP, but not the (dominant) compute while it's off.
resource autoShutdown 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  name: 'shutdown-computevm-${vmName}'
  location: location
  tags: tags
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: {
      time: autoShutdownTime
    }
    timeZoneId: autoShutdownTimeZone
    targetResourceId: vm.id
    notificationSettings: {
      status: 'Disabled'
    }
  }
}

// Azure Monitor Agent — the shipper. Idle until the DCR association below tells
// it what to collect.
resource ama 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  parent: vm
  name: 'AzureMonitorWindowsAgent'
  location: location
  tags: tags
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorWindowsAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
  }
}

// Sysmon install. Runs after AMA so extension operations on the VM don't race.
resource sysmon 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  parent: vm
  name: 'InstallSysmon'
  location: location
  tags: tags
  dependsOn: [
    ama
  ]
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'CustomScriptExtension'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: true
    protectedSettings: {
      commandToExecute: sysmonCommand
    }
  }
}

// AD DS promotion (Phase 2b). Runs LAST of the three extensions, and the order
// is load-bearing: promotion reboots the machine, so anything sequenced after
// it would be interrupted. Sysmon must already be installed and AMA must
// already be registered before the box drops.
//
// The extension reports success once promote-dc.ps1 exits; the restart it
// schedules happens ~60s later and the domain is live 2-4 minutes after that.
// A green deployment therefore means "promotion staged", not "domain ready" -
// verify with Get-ADDomain before running the seed script.
resource promoteDc 'Microsoft.Compute/virtualMachines/runCommands@2023-09-01' = if (promoteToDomainController) {
  parent: vm
  name: 'PromoteToDomainController'
  location: location
  tags: tags
  dependsOn: [
    ama
    sysmon
  ]
  properties: {
    source: {
      script: addsScript
    }
    // Passed to the script as named PowerShell parameters.
    parameters: [
      {
        name: 'DomainName'
        value: domainName
      }
      {
        name: 'NetbiosName'
        value: domainNetbiosName
      }
    ]
    // Encrypted, and omitted from a GET on the resource.
    protectedParameters: [
      {
        name: 'DsrmPassword'
        value: dsrmPassword
      }
    ]
    // Block the deployment on the result rather than firing and forgetting: a
    // promotion that silently failed would otherwise report a green deploy.
    asyncExecution: false
    treatFailureAsDeploymentFailure: true
    timeoutInSeconds: 2700
  }
}

// Bind this VM to the existing DCR. This is the line that turns collection on;
// depends on AMA being present first.
resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2022-06-01' = {
  name: '${vmName}-dcra'
  scope: vm
  dependsOn: [
    ama
  ]
  properties: {
    description: 'Associates the lab VM with the Windows security/Sysmon DCR.'
    dataCollectionRuleId: dataCollectionRuleId
  }
}

@description('Public IP address to RDP into (once allowedRdpSourceIp includes you).')
output publicIpAddress string = publicIp.properties.ipAddress

@description('VM resource ID.')
output vmId string = vm.id

@description('Whether this VM was deployed as a domain controller.')
output isDomainController bool = promoteToDomainController

@description('FQDN of the lab domain (empty unless promoteToDomainController = true). Sign in as <NetBIOS>\\<adminUsername> once the post-promotion restart completes.')
output labDomainName string = promoteToDomainController ? domainName : ''

@description('Static private IP of the domain controller, which is also the domain DNS server (empty unless promoteToDomainController = true).')
output domainControllerPrivateIp string = promoteToDomainController ? dcPrivateIp : ''
