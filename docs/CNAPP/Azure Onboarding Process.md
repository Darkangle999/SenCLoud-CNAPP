Azure changed classic admin behavior: Classic Service Administrator and Co-Administrator are retired. Do not rely on them. Azure onboarding now needs two separate approvals:
![[Pasted image 20260916130318.png]]
- Entra tenant admin: approves Odineyes enterprise application.
- Subscription **Owner** or **User Access Administrator**: assigns Azure RBAC access at subscription or resource-group scope. A Global Administrator alone does not automatically grant subscription access.
- Customer Entra tenant

  Admin consent
      |
      v
Odineyes multi-tenant Entra application
  Service principal created inside customer tenant
      |
      v
Customer subscription Owner / User Access Administrator
  assigns Reader + Security Reader
      |
      v
Odineyes Azure collector
  Azure Resource Graph + ARM + Defender APIs
      |
      v
Normalized inventory, findings, CIEM graph

![[Pasted image 20260916130448.png]]
Recommended workflow 
1. Register Odineyes as a **multi-tenant Entra application** in Odineyes tenant.
2. Use certificate or workload-federated credentials held only by Odineyes. Never request customer client secrets.
3. Customer clicks an **admin-consent link**. This creates Odineyes service principal in their Entra tenant.
4. Customer downloads or launches Odineyes ARM/Bicep onboarding template.
5. Their subscription Owner or User Access Administrator deploys it at:
    - subscription scope by default, or
    - selected resource groups for least privilege.
6. Template assigns Odineyes customer-tenant service principal:
    - `Reader` for inventory/configuration
    - `Security Reader` for Defender for Cloud posture
    - optional narrow monitoring roles for logs
7. Odineyes verifies token acquisition, subscription access, Resource Graph query, and selected scope.
8. Store `tenant_id`, `subscription_id`, `scope`, customer service-principal object ID, consent state, and last verification.
9. Later add Azure Activity Log diagnostic settings to Event Hub/Event Grid for real-time drift ingestion.

For Entra identity scanning, make it optional: request Microsoft Graph read permissions such as `Directory.Read.All`, `Policy.Read.All`, and `AuditLog.Read.All` only when customer enables Identity Security. That consent requires stronger Entra administration approval.

In an MNC, Odineyes should never ask for root, Global Administrator, Owner, or permanent admin access.

But hard boundary: if customer gives no approved read access and no approved security-data export, full visibility is impossible. Product must show that as a coverage gap, not pretend environment is safe.

Customer security team controls access
        |
        +-- Deploy approved read-only connector
        +-- Or export central security/configuration data
        |
Odineyes receives scoped evidence only
        |
Normalized asset + identity + network graph
        |
Cross-cloud risk correlation with coverage confidence

## When we have a MNC Case

Do not ask for Global Administrator access.

- Customer Entra admin grants consent for Odineyes enterprise application only if Identity Security module is enabled.
- Customer subscription Owner or User Access Administrator deploys ARM/Bicep once.
- Assign Odineyes service principal `Reader` and `Security Reader` at selected subscription/resource-group scope.
- Use Azure Resource Graph for centralized inventory.
- Use Defender for Cloud export to Event Hub/Log Analytics for findings and drift.
- Optional Azure Lighthouse for multi-subscription, multi-tenant delegation. Lighthouse supports delegated built-in roles, but not Owner or custom roles.

Some MNCs prohibit third-party cross-account trust entirely. Support a customer-hosted collector.

- Azure: customer deploys container/function with managed identity.
- Collector reads only approved scopes.
- Collector sends signed, compressed normalized observations outbound over HTTPS.
- No inbound network access. No customer secrets shared. Customer can stop/delete collector instantly.

This gives Odineyes data without Odineyes holding privileged access inside customer cloud.

## User-level onboarding

This flow allows Azure users to sign into Odineyes. It should not run background scans using that user’s session.

### Flow

```
User selects “Sign in with Microsoft”
        |
Microsoft Entra authenticates user
        |
Odineyes validates issuer, tenant and token
        |
Tenant policy checks organization allowlist
        |
Entra groups/app roles map to Odineyes roles
        |
User receives Odineyes session
```

### Odineyes roles

Map Entra application roles or approved groups into:

- `OrganizationAdmin`: manages Odineyes tenant configuration.
- `CloudAdmin`: creates onboarding sessions and connectors.
- `SecurityAnalyst`: investigates findings and attack paths.
- `Auditor`: read-only compliance and evidence access.
- `BillingAdmin`: subscription and usage only.

Do not infer Odineyes privileges from Azure `Owner`, `Contributor`, or Entra Global Administrator. Product permissions should remain independent.

### External organization controls

Customer can add the Odineyes Entra tenant under:

```
Entra ID
External Identities
Cross-tenant access settings
Organizational settings
```

They can then:

- Allow only approved Odineyes users/groups.
- Allow only the Odineyes application.
- Require MFA.
- Trust MFA or compliant-device claims from the user’s home organization.
- Block all other external applications.
- Apply Conditional Access to guest sessions.

Cross-tenant settings can target organizations, users, groups and applications independently. [Microsoft cross-tenant configuration](https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-settings-b2b-collaboration)

### Why delegated user access is insufficient for scanning

Odineyes could request delegated ARM permissions and scan using a signed-in user’s token, but this creates serious limitations:

- Scan stops when session or refresh token expires.
- Visibility depends on that user’s RBAC assignments.
- Employee departure breaks connector.
- MFA and Conditional Access can interrupt scheduled jobs.
- Audit trail attributes machine scans to a human.
- A user might have more access than Odineyes requires.

Use delegated user access only for interactive features, such as “show subscriptions I can onboard.”

## 3. Organization-level onboarding: recommended SaaS model

Use an Odineyes multi-tenant Entra application.

### Platform-side preparation

Odineyes creates one application registration in its own Entra tenant:

```
Application: Odineyes CSPM Connector
Supported account type: Multitenant
Authentication: certificate or federated workload identity
Publisher verification: enabled
Redirect URI: public Odineyes onboarding callback
```

Do not create a client secret in the customer tenant. The customer only receives a service-principal representation of the Odineyes application. A service principal must exist in every tenant where a multi-tenant application operates.

Do not create a client secret in the customer tenant. The customer only receives a service-principal representation of the Odineyes application. A service principal must exist in every tenant where a multi-tenant application operates.
### Customer onboarding flow

```
1. Create Odineyes onboarding session
2. Customer opens Microsoft admin-consent URL
3. Customer reviews requested permissions
4. Entra creates Odineyes enterprise application/service principal
5. Customer selects management group, subscription or resource-group scope
6. Customer deploys ARM/Bicep role-assignment template
7. Odineyes verifies tenant and scope
8. Initial Resource Graph inventory runs
9. Optional identity and real-time modules are enabled separately
```

### Required customer administrators

No administrator credentials are given to Odineyes.

Customer personnel use elevated access only during setup:

- Application consent: Application Administrator, Cloud Application Administrator or Privileged Role Administrator depending on requested permissions.
- Azure RBAC assignment: Owner, User Access Administrator or Role Based Access Control Administrator at the selected scope.

Microsoft recommends reviewing tenant-wide application consent carefully. Microsoft Graph application permissions need stronger approval than basic application provisioning
## Azure RBAC package

### Baseline CSPM roles

Assign these to the customer-tenant Odineyes service principal:

|Role|Role ID|Purpose|
|---|---|---|
|Reader|`acdd72a7-3385-48ef-bd42-f606fba81ae7`|Resource configuration and Resource Graph|
|Security Reader|`39bc4728-0917-49c7-9d2c-d95423bc2eb4`|Defender recommendations, alerts and security posture|

`Reader` views resources without modifying them. `Security Reader` views Defender for Cloud recommendations, alerts, policies and security states.

### Scope choices

#### Resource-group onboarding

Use when customer wants a pilot or business-unit boundary.

```
Scope: /subscriptions/{subscription}/resourceGroups/{resource-group}
```

Visibility is restricted to that resource group. Cross-resource attack paths outside it will be partial.

#### Subscription onboarding

Recommended default.

```
Scope: /subscriptions/{subscription}
```

Odineyes discovers all permitted resources and resource groups in that subscription.

#### Management-group onboarding

Recommended for a single-tenant MNC.

```
Scope: /providers/Microsoft.Management/managementGroups/{management-group}
```

Role inheritance can provide visibility into descendant subscriptions. Customer can choose a dedicated management group containing only approved subscriptions.

Azure RBAC supports role assignments at resource, resource-group, subscription and management-group scope. Microsoft recommends using the smallest scope that satisfies the requirement.

## 5. Identity Security module

Azure resource access and Entra directory visibility are separate.

`Reader` does not provide complete visibility into:

- Users and groups.
- Application registrations.
- Enterprise applications.
- Directory roles.
- Conditional Access policies.
- Sign-in and audit logs.

Odineyes should offer an optional second consent step:

```
Enable Azure Identity Security
```

It may request reviewed Microsoft Graph application permissions such as directory, application, policy, role-management and audit-log read permissions. Exact permissions should be generated from implemented collectors rather than requesting broad Graph access prematurely.

Product must display two independent coverage indicators:

```
Azure Resource Coverage: Complete
Entra Identity Coverage: Not enabled
```

Do not label overall coverage complete when Graph consent is absent.

## 6. Azure Lighthouse option

For managed services or multi-tenant enterprises, Azure Lighthouse delegates subscriptions or resource groups to identities in the Odineyes managing tenant.

Customer deploys an ARM template containing:

- `managedByTenantId`: Odineyes tenant ID.
- `principalId`: Odineyes security group or service principal.
- `roleDefinitionId`: Reader/Security Reader.
- Registration definition.
- Registration assignment.

Lighthouse supports built-in roles but does not support Owner, custom roles or most roles containing privileged authorization writes or `DataActions`. This fits CSPM control-plane scanning but not arbitrary data-plane inspection.

Lighthouse does not replace Microsoft Graph consent for Entra identity analysis.

## 7. Strict MNC model: customer-hosted collector

If customer prohibits third-party enterprise applications or cross-tenant delegation:

```
Customer Azure tenant
└── Odineyes Collector
    ├── Azure Container Apps / VM / AKS
    ├── Customer-managed identity
    ├── Reader + Security Reader
    └── Outbound HTTPS to Odineyes
```

The customer:

- Owns collector.
- Owns managed identity.
- Controls network egress.
- Controls role assignments.
- Can inspect the container image.
- Can stop or remove connector immediately.

Collector sends normalized metadata and findings, not credentials. This should be a first-class onboarding option for regulated MNC customers.

## 8. Proposed Odineyes UI workflow

```
Connect Azure
│
├── Access model
│   ├── Odineyes multi-tenant application
│   ├── Azure Lighthouse
│   └── Customer-hosted collector
│
├── Coverage
│   ├── Resource groups
│   ├── Subscriptions
│   └── Management group
│
├── Permissions
│   ├── Reader
│   ├── Security Reader
│   └── Optional Identity Security
│
├── Approval
│   ├── Admin consent
│   └── Azure RBAC deployment
│
├── Verification
│   ├── Token acquisition
│   ├── Subscription discovery
│   ├── Resource Graph query
│   ├── Defender query
│   └── Graph query when enabled
│
└── Initial scan
```

## 9. Required backend model

Create separate records instead of extending AWS `role_arn` fields:

```
AzureTenant
- id
- organization_id
- tenant_id
- display_name
- onboarding_mode
- application_id
- service_principal_object_id
- consent_status
- identity_consent_status
- connection_status
- last_verified_at

AzureScope
- azure_tenant_id
- scope_type
- management_group_id
- subscription_id
- resource_group_name
- role_assignments
- coverage_status
- last_scanned_at

AzureOnboardingSession
- session_id
- state_hash
- requested_by
- expires_at
- redeemed_at
- selected_mode
- requested_scopes
- status
```

Never store customer administrator passwords, browser tokens or client secrets.

## 10. Narrow implementation order

### Phase 1: resource onboarding

- Multi-tenant Entra application.
- Admin-consent callback.
- Customer service-principal discovery.
- Downloadable ARM/Bicep RBAC template.
- Reader and Security Reader.
- Subscription-level onboarding.
- Resource Graph inventory.
- Connection verification and revocation.

### Phase 2: enterprise scope

- Management-group discovery.
- Multiple subscriptions.
- Azure Lighthouse package.
- Coverage matrix.
- Incremental scanning.

### Phase 3: identity and real-time

- Optional Microsoft Graph consent.
- Entra identity graph.
- Azure Activity Log and Defender continuous export.
- Event Hub ingestion.
- Cross-cloud attack-path correlation.

The most important design rule: **External Identities authenticates people; service principals, managed identities and Azure Lighthouse authorize CSPM workloads.** Mixing those models will produce fragile scans and excessive human privilege.






















































































































































































































































