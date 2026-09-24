# Discord adapter beta

**Status:** scaffolding, disabled by default. Double-gated: the `discord`
Cargo feature must be enabled **and** `LUMEN_MESSAGING_DISCORD=1` (or
`MessagingConfig.discord_enabled = true`), otherwise `bind` refuses with
`AdapterError::Disabled`.

## What's implemented

- **Official bot/application surface only.** No user-token automation, no
  unofficial libraries for auth. References:
  <https://docs.discord.com/developers/bots/overview>.
- **Real interaction signature verification** (`verify_interaction_signature`):
  Ed25519 over `timestamp + body` with the application public key, from the
  `X-Signature-Ed25519` / `X-Signature-Timestamp` headers. Covered by a test
  with a fixed keypair (valid signature verifies; wrong timestamp, tampered
  body, and wrong key all fail).
- **Minimum intents** (`DiscordIntents::minimum`): `guilds` + `direct_messages`
  only — no privileged intents. `message_content` and `guild_members` are
  explicit opt-ins; `requests_privileged()` reports when they're set (needs
  Discord approval on the application).
- **Explicit guild/channel mapping** (`DiscordBotConfig`): non-empty
  `allowed_guilds` / `allowed_channels` admit only listed ids; everything
  else fails closed at ingest. DMs are separately gated by `allow_dms`.
- **Typed policy resources** (`DiscordResource`): `discord.guild`,
  `discord.channel`, `discord.thread`, `discord.dm` for
  `ResourceScope::exact` lease scoping.
- **Command/reply flows**: `DiscordGatewayEvent` (message + interaction
  kinds) ingests into `MessageEnvelope`; `build_rest_call` produces the
  exact Discord REST shapes (`POST /channels/{id}/messages`, `PATCH`
  message, `PUT` reaction, `DELETE` message) for the host to execute.

## Credential model

The bot token is brokered host-side. The adapter holds only the opaque
`CredentialHandle`; `DiscordRestCall` describes the HTTP call and the host
executes it with the kernel-brokered token (`Authorization: Bot <token>`).
`execute_outbound` fails closed and points at `build_rest_call` — the
adapter never touches the network or the token.

## Beta follow-ups (not in this phase)

1. Host REST executor: executes `DiscordRestCall` with the brokered token,
   records provider receipts, enforces rate limits.
2. Gateway client for live event streaming (replacing host-polled ingest).
3. Attachment download via CDN URLs through the quarantine pipeline.
4. Thread/moderation verbs beyond the current send/edit/react/delete mapping.

## Rollback

Unset `LUMEN_MESSAGING_DISCORD` or build without the `discord` feature;
`AdapterRegistry::disable("discord")` revokes the connection and
invalidates the credential handle. The kernel and other adapters are
unaffected.
