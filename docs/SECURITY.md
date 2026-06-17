# Security Model

Lumen is safe by default. The runtime should assume that agent actions need accountability, approval boundaries, and clear ownership.

## Goals

- Only approved users and channels can interact with the agent.
- Risky tasks require explicit approval.
- Every meaningful action is traceable.
- Plugins run with declared and enforced permissions.
- Local-first operation keeps user data close to user-owned infrastructure.

## Identity and Allowlisting

Chats and external requests should only be accepted from explicitly approved identities.

Examples of allowlisted identities:

- Local web users
- Chat platform users
- Chat channels
- Workspace members
- Service accounts

The runtime should reject unknown users and channels by default.

## Approval Gates

Risky actions should require explicit approval before execution.

Examples:

- Writing to external systems
- Sending messages to other people
- Running shell commands
- Installing or updating plugins
- Changing permissions
- Deleting or overwriting data
- Scheduling recurring jobs
- Touching production systems

Approval records should be connected to the final audit event.

## Audit Trail

The audit log should capture:

- What happened
- When it happened
- Who requested it
- Which agent, job, plugin, or tool acted
- Which plugin hash or version was involved
- What permission checks were performed
- What systems were touched
- Whether approval was requested and granted
- Whether the action succeeded or failed

The audit trail is a core product feature, not an afterthought.

## Plugin Security

Plugins should declare required permissions. The runtime should enforce those permissions before plugin actions can touch sensitive resources.

Plugin records should include cryptographic hashes so Lumen can verify what plugin code/config was used when an action happened.

## Local Secrets

Secrets should not be stored in plain runtime settings unless there is no safer option. The first implementation should define a local secret storage approach before plugins need API keys or credentials.

Possible approaches:

- OS keychain integration
- Encrypted local secrets file
- Environment variables for bootstrap-only secrets
- External secret manager plugin

## Non-Goals

Lumen should not assume that local-first means security is automatic. Local execution reduces exposure to hosted services, but it does not remove the need for permissions, approvals, isolation, and auditing.
