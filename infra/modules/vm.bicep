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

var computerName = take(replace(vmName, '-', ''), 15)

// Fail-closed RDP source: never fall back to '*'. An unroutable /32 = nobody.
var rdpSource = empty(allowedRdpSourceIp) ? '255.255.255.255/32' : allowedRdpSourceIp

// Sysmon install runs entirely inline (no external script host): the config is
// embedded as base64 from sysmonconfig.xml, and every PowerShell string literal
// is single-quoted so nothing collides with the outer -Command "..." quotes.
var sysmonConfigB64 = base64(loadTextContent('sysmonconfig.xml'))
var sysmonCommand = 'powershell -ExecutionPolicy Unrestricted -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; [IO.File]::WriteAllBytes(\'C:\\Windows\\Temp\\sysmonconfig.xml\',[Convert]::FromBase64String(\'${sysmonConfigB64}\')); Invoke-WebRequest -Uri \'${sysmonDownloadUrl}\' -OutFile \'C:\\Windows\\Temp\\Sysmon.zip\' -UseBasicParsing; Expand-Archive -Path \'C:\\Windows\\Temp\\Sysmon.zip\' -DestinationPath \'C:\\Windows\\Temp\\Sysmon\' -Force; & \'C:\\Windows\\Temp\\Sysmon\\Sysmon64.exe\' -accepteula -i \'C:\\Windows\\Temp\\sysmonconfig.xml\'"'

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
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
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
