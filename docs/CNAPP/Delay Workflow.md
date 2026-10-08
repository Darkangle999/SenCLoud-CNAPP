
```
AB = business/team lead, requested Odineyes
BD = cloud-access owner, can deploy connector
AB unavailable
BD cannot get approval or does not want product
```

Odineyes must never bypass AB or create cloud access itself.

Use onboarding states:

```
Draft
  |
Awaiting business approval
  |
Awaiting cloud-owner deployment
  |
Stack deployed
  |
Verification pending
  |
Active
```

Recommended behavior:

- AB creates onboarding request and names BD as cloud-access owner.
- BD receives only a reviewed CloudFormation/ARM/Bicep package and scope summary.
- BD can deploy only after business/security approval exists.
- If AB is unavailable, BD can nominate an approved delegate such as security lead, platform manager, or change-management approver.
- Odineyes remains `Pending`, collects no cloud data, starts no scan, and sends no misleading “protected” status.

Important token design:

- ExternalId can remain stable per customer account.
- One-click URL and callback token must expire quickly, such as 1 hour.
- If approval comes later, user clicks **Regenerate launch link**. Never keep old callback tokens valid for days.

For a rejected product:

```
Rejected / Closed
```

Our Product should:

- Revoke onboarding token/session immediately.
- Disable callback acceptance.
- Stop all pending scan jobs.
- Mark coverage as `not onboarded`.
- Preserve only minimal audit metadata: requester, approver/rejector, date, reason.
- Never delete customer cloud resources automatically.
- If customer already deployed stack, show them a customer-controlled teardown template/instructions.

If a delayed stack later calls back after rejection, API must reject it. Do not activate account.

Best enterprise UI fields:

- Business owner: AB
- Cloud access owner: BD
- Security approver
- Backup approver
- Change ticket: ServiceNow/Jira ID
- Requested scope: accounts/subscriptions/regions
- Expiry time
- Current blocker
- Last reminder
- Revoke onboarding button

No long-running backend “wait.” Store status in DB, use short-lived callbacks, and notify through email/Slack/ServiceNow only on state change.

This gives MNC teams control: AB approves business need, BD controls infrastructure access, security controls trust, and Odineyes only activates after all required evidence exists.