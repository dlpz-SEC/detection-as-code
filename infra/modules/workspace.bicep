// Log Analytics workspace + Microsoft Sentinel onboarding.
//
// Two things here are load-bearing for the lab's cost model:
//
//   1. workspaceCapping.dailyQuotaGb — stops ingestion once the day's quota is
//      hit. A subscription budget alert only sends mail after money is spent;
//      this refuses the data. Two caveats worth knowing: the cap overshoots
//      (Microsoft documents that some data past the limit is still ingested and
//      billed), and it only governs BILLABLE tables — free tables such as
//      AzureActivity, SecurityAlert and SecurityIncident keep flowing. Since
//      18 September 2023 the cap does apply to security tables, so it also
//      bounds a runaway Sentinel connector.
//   2. retentionInDays: 90 — free for as long as Sentinel is onboarded on this
//      workspace (plain Log Analytics includes 31 days). Retention beyond 90
//      bills per GB per month and keeps billing after teardown if the workspace
//      survives. If Sentinel is ever removed while the workspace lives on, the
//      free window drops back to 31 days and days 32-90 start billing.

@description('Log Analytics workspace name.')
param workspaceName string

@description('Azure region.')
param location string

@description('Daily ingestion cap in GB. Applies to billable tables; overshoot past the cap is still billed.')
@minValue(1)
param dailyQuotaGb int

@description('Retention in days. 90 is free on a Sentinel-enabled workspace; beyond that bills per GB per month.')
@minValue(30)
@maxValue(730)
param retentionInDays int

@description('Tags applied to the workspace.')
param tags object

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      // PerGB2018 is the only sku that the Sentinel free trial applies against.
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
    features: {
      // Access control mode. true = resource-context ("Use resource or workspace
      // permissions"), the Azure default for workspaces created after March 2019,
      // and the mode that enables granular per-resource RBAC.
      //
      // It does NOT restrict access to the workspace — the opposite: a principal
      // holding */read inherited from the subscription or resource group can read
      // this workspace's logs in resource context, and workspace permissions are
      // ignored on that path. false ("Require workspace permissions") is the
      // restrictive setting, at the cost of granular RBAC.
      //
      // Either way this flag is not the lab's least-privilege control: ADTE's
      // reader service principal queries at workspace scope and needs
      // Microsoft.OperationalInsights/workspaces/query/read on this workspace
      // regardless. That role assignment is made out-of-band, not in this
      // template.
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Onboards Microsoft Sentinel onto the workspace. This is what starts the
// 31-day Sentinel trial clock on a new workspace.
resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2022-12-01-preview' = {
  scope: workspace
  name: 'default'
  properties: {}
}

@description('Workspace GUID (customerId) — the value ADTE reads as ADTE_SENTINEL_WORKSPACE_ID.')
output workspaceId string = workspace.properties.customerId

@description('Full ARM resource ID, used to target the workspace from a DCR.')
output workspaceResourceId string = workspace.id

@description('Workspace name, echoed for convenience in deployment output.')
output workspaceName string = workspace.name
