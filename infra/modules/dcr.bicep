// Data Collection Rule — Windows security and Sysmon events, XPath-filtered.
//
// This is the cost-engineering surface of the lab. The Azure Monitor Agent sends
// what a DCR tells it to send, and "all security events" from a single Windows
// VM running Atomic Red Team will comfortably exhaust a 1 GB/day cap on its own.
//
// So the XPath queries below are deliberately narrow: the specific event IDs the
// detection corpus actually keys on, not a severity bucket. Widening this is a
// spending decision, not a config tweak — the events added here are the events
// billed for.
//
// Event IDs and what consumes them (verified against rules/, not assumed):
//   4625 failed logon   -> bruteforce_failures_then_success, password_spray_single_source
//   4624 successful logon -> no detection selection; collected as investigation
//                            context, since bruteforce_failures_then_success asks
//                            the analyst to confirm a subsequent success
//   Sysmon EID 1  (process creation) -> powershell_encoded_command
//   Sysmon EID 10 (process access)   -> lsass_memory_access
//
// Deliberately NOT collected: 4672, 4720, 4732, 4688. No rule in rules/ matches
// them, so they were billed ingestion with no consumer. 4688 in particular
// duplicates Sysmon EID 1, which is richer. Add one back only alongside the rule
// that needs it — the Windows live-fire phase is the moment to revisit this.
//
// Stream choice silently decides the destination TABLE, and nothing else records
// this:
//   'Microsoft-SecurityEvent' -> SecurityEvent table
//   'Microsoft-Event'         -> Event table (NOT SysmonEvent, NOT WindowsEvent)
// Sysmon rows land in Event with Source == 'Microsoft-Windows-Sysmon' and their
// fields (Image, CommandLine, TargetImage, GrantedAccess) inside the rendered
// EventData rather than as first-class columns — KQL against them needs parsing.
// Anything written against a SysmonEvent table returns zero rows with no error.
//
// The DCR is inert until a VM is associated with it
// (Microsoft.Insights/dataCollectionRuleAssociations), which happens in the
// Windows live-fire phase — not here.

@description('Azure region. Must match the region of the destination Log Analytics workspace; VMs associated via a DCRA may live elsewhere.')
param location string

@description('ARM resource ID of the destination Log Analytics workspace.')
param workspaceResourceId string

@description('Name of the data collection rule.')
param dataCollectionRuleName string = 'dcr-windows-security-events'

@description('Tags applied to the rule.')
param tags object

resource dataCollectionRule 'Microsoft.Insights/dataCollectionRules@2022-06-01' = {
  name: dataCollectionRuleName
  location: location
  tags: tags
  kind: 'Windows'
  properties: {
    description: 'XPath-filtered Windows security and Sysmon events for the detection lab. Narrow by design: every added event ID is billed ingestion.'
    dataSources: {
      windowsEventLogs: [
        {
          name: 'securityEvents'
          streams: [
            'Microsoft-SecurityEvent'
          ]
          xPathQueries: [
            'Security!*[System[(EventID=4624)]]'
            'Security!*[System[(EventID=4625)]]'
          ]
        }
        {
          name: 'sysmonEvents'
          streams: [
            'Microsoft-Event'
          ]
          xPathQueries: [
            'Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1 or EventID=10)]]'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          name: 'labWorkspace'
          workspaceResourceId: workspaceResourceId
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-SecurityEvent'
        ]
        destinations: [
          'labWorkspace'
        ]
      }
      {
        streams: [
          'Microsoft-Event'
        ]
        destinations: [
          'labWorkspace'
        ]
      }
    ]
  }
}

@description('ARM resource ID of the DCR — needed to associate a VM with it later.')
output dataCollectionRuleId string = dataCollectionRule.id

@description('DCR name.')
output dataCollectionRuleName string = dataCollectionRule.name
