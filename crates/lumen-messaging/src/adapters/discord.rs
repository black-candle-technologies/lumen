//! Discord adapter: official bot/application integration (scoped beta).
//!
//! # Status
//!
//! Scaffolding behind a double gate: the `discord` Cargo feature must be
//! enabled **and** `MessagingConfig.discord_enabled` must be true, otherwise
//! [`DiscordAdapter::bind`] refuses with [`AdapterError::Disabled`].
//!
//! What is real in this beta:
//! - [`verify_interaction_signature`]: genuine Ed25519 verification of
//!   Discord interaction webhooks (`X-Signature-Ed25519` /
//!   `X-Signature-Timestamp` over `timestamp + body`), per
//!   <https://docs.discord.com/developers/bots/overview>.
//! - Explicit guild/channel allowlists; events outside them fail closed.
//! - Typed policy resources ([`DiscordResource`]) for lease scoping.
//! - Exact REST call descriptors ([`DiscordRestCall`]) for send/edit/react/
//!   delete, executed by the host with the kernel-brokered bot token.
//!
//! What is intentionally *not* here yet (beta follow-ups, see
//! `docs/messaging/discord-beta.md`): a live Gateway client and a host REST
//! executor. [`MessagingAdapter::execute_outbound`] therefore fails closed
//! and directs callers to [`DiscordAdapter::build_rest_call`], whose output
//! the host executes with the brokered credential. The adapter never sees
//! the bot token — it only holds the opaque [`CredentialHandle`].

use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    MessagingConfig,
    adapters::{
        AdapterCapabilities, AdapterDescriptor, AdapterError, AdapterVersion, ConnectionBinding,
        ConnectionState, CredentialHandle, DedupeDecision, IngestError, MessagingAdapter,
        ProviderReceipt,
    },
    dedupe::DedupeStore,
    envelope::{
        ConnectionId, Conversation, DedupeKey, MessageEnvelope, Provenance, Provider,
        ProviderMessageId, ReplyContext, SenderIdentity, TransportTrust,
    },
    outbound::{OutboundRequest, OutboundTarget, OutboundVerb},
    principals::{PrincipalMappingRegistry, PrincipalResolution},
};

/// Reviewed adapter version for audit provenance.
pub const ADAPTER_VERSION: &str = "0.1.0";

/// Gateway intents for the bot application. Only non-privileged intents are
/// enabled by default; privileged intents are explicit opt-ins.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscordIntents {
    /// Non-privileged. Guild/channel/thread metadata for routing.
    pub guilds: bool,
    /// Non-privileged. Direct messages the bot receives.
    pub direct_messages: bool,
    /// PRIVILEGED. Required to read message *content* in guild channels.
    /// Disabled by default; slash-command interactions do not need it.
    pub message_content: bool,
    /// PRIVILEGED. Guild member lists. Disabled by default.
    pub guild_members: bool,
}

impl DiscordIntents {
    /// Minimum viable intents: DMs plus guild metadata, no privileged intents.
    pub fn minimum() -> Self {
        Self {
            guilds: true,
            direct_messages: true,
            message_content: false,
            guild_members: false,
        }
    }

    /// True when any privileged intent is requested (needs Discord approval
    /// on the application).
    pub fn requests_privileged(&self) -> bool {
        self.message_content || self.guild_members
    }
}

/// Bot application configuration. The token itself is brokered host-side;
/// this struct carries only the opaque handle.
#[derive(Clone, Debug)]
pub struct DiscordBotConfig {
    pub application_id: String,
    /// Ed25519 public key (hex) from the Discord developer portal, used to
    /// verify interaction webhook signatures.
    pub application_public_key_hex: String,
    pub token_handle: CredentialHandle,
    /// When non-empty, only these guilds are admitted; everything else fails
    /// closed at ingest.
    pub allowed_guilds: Vec<String>,
    /// When non-empty, only these channels are admitted.
    pub allowed_channels: Vec<String>,
    pub allow_dms: bool,
    pub intents: DiscordIntents,
}

impl DiscordBotConfig {
    pub fn validate(&self) -> Result<(), DiscordError> {
        if self.application_id.is_empty() || self.application_id.len() > 64 {
            return Err(DiscordError::InvalidConfig("application_id"));
        }
        // The public key must decode to 32 bytes now, not at first webhook.
        decode_public_key(&self.application_public_key_hex)?;
        Ok(())
    }
}

/// Typed policy resource for Discord lease scoping.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum DiscordResource {
    Guild(String),
    Channel(String),
    Thread(String),
    DirectMessage(String),
}

impl DiscordResource {
    /// `resource_type` for [`lumen_core::capability::ResourceScope::exact`].
    pub const fn resource_type(&self) -> &'static str {
        match self {
            Self::Guild(_) => "discord.guild",
            Self::Channel(_) => "discord.channel",
            Self::Thread(_) => "discord.thread",
            Self::DirectMessage(_) => "discord.dm",
        }
    }

    pub fn value(&self) -> &str {
        match self {
            Self::Guild(id) | Self::Channel(id) | Self::Thread(id) | Self::DirectMessage(id) => id,
        }
    }
}

/// Verifies a Discord interaction webhook signature.
///
/// Discord signs `timestamp + body` with the application's Ed25519 key and
/// sends the hex signature in `X-Signature-Ed25519` and the timestamp in
/// `X-Signature-Timestamp`. This is the real verification, not a stub.
pub fn verify_interaction_signature(
    application_public_key_hex: &str,
    signature_hex: &str,
    timestamp: &str,
    body: &[u8],
) -> Result<(), DiscordError> {
    let public_key = decode_public_key(application_public_key_hex)?;
    let signature_bytes = hex::decode(signature_hex).map_err(|_| DiscordError::BadSignature)?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| DiscordError::BadSignature)?;

    let mut message = Vec::with_capacity(timestamp.len() + body.len());
    message.extend_from_slice(timestamp.as_bytes());
    message.extend_from_slice(body);

    public_key
        .verify(&message, &signature)
        .map_err(|_| DiscordError::BadSignature)
}

fn decode_public_key(hex_str: &str) -> Result<VerifyingKey, DiscordError> {
    let bytes = hex::decode(hex_str).map_err(|_| DiscordError::BadPublicKey)?;
    VerifyingKey::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| DiscordError::BadPublicKey)?,
    )
    .map_err(|_| DiscordError::BadPublicKey)
}

/// Normalized inbound Discord event (produced by the host's Gateway/HTTP
/// edge after authenticating the session; interaction webhooks additionally
/// pass through [`verify_interaction_signature`]).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct DiscordGatewayEvent {
    pub kind: DiscordEventKind,
    #[serde(default)]
    pub guild_id: Option<String>,
    pub channel_id: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    pub author_id: String,
    #[serde(default)]
    pub author_name: Option<String>,
    pub message_id: String,
    #[serde(default)]
    pub content: String,
    pub timestamp_ms: i64,
    /// For interaction events: the invoked command name.
    #[serde(default)]
    pub command_name: Option<String>,
    /// Id of the message being replied to, if any.
    #[serde(default)]
    pub reply_to_message_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DiscordEventKind {
    Message,
    Interaction,
}

/// Outcome of [`DiscordAdapter::ingest_signed_interaction`].
#[derive(Debug)]
pub enum SignedInteractionOutcome {
    /// Discord endpoint validation (`type: 1`): the host must answer
    /// `{"type":1}`; there is nothing to ingest.
    Ping,
    /// Ingested interaction event (`None` when it was a known redelivery).
    /// Boxed: the envelope is large and this enum crosses call boundaries.
    Event(Option<Box<MessageEnvelope>>),
}

/// Wire shape of a Discord interaction webhook body
/// (<https://docs.discord.com/developers/interactions/receiving-and-responding#interaction-object>).
/// Only the fields the adapter maps are modeled.
#[derive(Clone, Debug, Deserialize)]
struct DiscordInteraction {
    #[serde(rename = "type")]
    kind: u8,
    id: String,
    #[serde(default)]
    guild_id: Option<String>,
    #[serde(default)]
    channel_id: Option<String>,
    #[serde(default)]
    channel: Option<InteractionChannel>,
    #[serde(default)]
    member: Option<InteractionMember>,
    #[serde(default)]
    user: Option<InteractionUser>,
    #[serde(default)]
    data: Option<InteractionData>,
}

#[derive(Clone, Debug, Deserialize)]
struct InteractionChannel {
    id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct InteractionMember {
    #[serde(default)]
    nick: Option<String>,
    user: InteractionUser,
}

#[derive(Clone, Debug, Deserialize)]
struct InteractionUser {
    id: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    global_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct InteractionData {
    #[serde(default)]
    name: Option<String>,
}

impl DiscordInteraction {
    /// Maps the webhook body onto the normalized gateway event shape:
    /// interaction `id` becomes the message id, `member.user.id` (or
    /// `user.id`) becomes the author.
    fn into_gateway_event(self, timestamp_ms: i64) -> Result<DiscordGatewayEvent, IngestError> {
        let malformed = |reason: &str| IngestError::MalformedEvent {
            reason: reason.to_owned(),
        };
        let channel_id = self
            .channel
            .map(|c| c.id)
            .or(self.channel_id)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| malformed("interaction has no channel"))?;
        let (author_id, author_name) = match (self.member, self.user) {
            (Some(member), _) => {
                let name = member
                    .nick
                    .or(member.user.global_name)
                    .or(member.user.username);
                (member.user.id, name)
            }
            (None, Some(user)) => {
                let name = user.global_name.or(user.username);
                (user.id, name)
            }
            (None, None) => return Err(malformed("interaction has no author")),
        };
        if author_id.is_empty() {
            return Err(malformed("interaction has no author"));
        }
        let command_name = self.data.as_ref().and_then(|d| d.name.clone());
        let content = command_name
            .as_deref()
            .map(|name| format!("/{name}"))
            .unwrap_or_default();
        Ok(DiscordGatewayEvent {
            kind: DiscordEventKind::Interaction,
            guild_id: self.guild_id,
            channel_id,
            thread_id: None,
            author_id,
            author_name,
            message_id: self.id,
            content,
            timestamp_ms,
            command_name,
            reply_to_message_id: None,
        })
    }
}

/// Maximum age of the authenticated `X-Signature-Timestamp` header, in
/// seconds. The signature authenticates this header, so a captured webhook
/// cannot be replayed outside the window (future timestamps are rejected
/// too, which also bounds clock skew).
const INTERACTION_TIMESTAMP_WINDOW_SECS: i64 = 300;

/// Parses the authenticated interaction timestamp header as Unix seconds and
/// enforces the freshness window against `now_millis`. Returns millis for
/// the normalized event.
fn parse_interaction_timestamp(timestamp: &str, now_millis: i64) -> Result<i64, IngestError> {
    let malformed = |reason: &str| IngestError::MalformedEvent {
        reason: reason.to_owned(),
    };
    let secs: i64 = timestamp
        .parse()
        .map_err(|_| malformed("interaction timestamp header is not unix seconds"))?;
    let skew_secs = now_millis.div_euclid(1000) - secs;
    if skew_secs.abs() > INTERACTION_TIMESTAMP_WINDOW_SECS {
        return Err(malformed("interaction timestamp outside freshness window"));
    }
    Ok(secs.saturating_mul(1000))
}

/// Exact Discord REST call for an outbound effect. The host executes this
/// with the kernel-brokered bot token (`Authorization: Bot <token>`); the
/// adapter never sees the token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscordRestCall {
    pub method: &'static str,
    pub url: String,
    pub body_json: String,
}

impl DiscordRestCall {
    fn post_channel_message(channel_id: &str, content: &str) -> Self {
        Self {
            method: "POST",
            url: format!("https://discord.com/api/v10/channels/{channel_id}/messages"),
            body_json: serde_json::json!({ "content": content }).to_string(),
        }
    }
}

pub struct DiscordAdapter {
    descriptor: AdapterDescriptor,
    bot_config: DiscordBotConfig,
    registry: Arc<PrincipalMappingRegistry>,
    dedupe: Arc<dyn DedupeStore>,
    binding: Option<ConnectionBinding>,
    state: ConnectionState,
}

impl DiscordAdapter {
    pub fn new(
        bot_config: DiscordBotConfig,
        registry: Arc<PrincipalMappingRegistry>,
        dedupe: Arc<dyn DedupeStore>,
    ) -> Result<Self, DiscordError> {
        bot_config.validate()?;
        Ok(Self {
            descriptor: AdapterDescriptor::new(
                "discord",
                AdapterVersion::new(ADAPTER_VERSION).expect("adapter version is valid"),
                AdapterCapabilities {
                    inbound_events: vec![
                        "message.created".to_owned(),
                        "interaction.created".to_owned(),
                    ],
                    outbound_verbs: vec![
                        "send".to_owned(),
                        "edit".to_owned(),
                        "react".to_owned(),
                        "delete".to_owned(),
                    ],
                },
            ),
            bot_config,
            registry,
            dedupe,
            binding: None,
            state: ConnectionState::Unbound,
        })
    }

    /// Verifies an interaction webhook's Ed25519 signature and ingests it.
    ///
    /// Signed webhook bodies are Discord's *interaction* schema, not the
    /// normalized [`DiscordGatewayEvent`] (that type is for host-authenticated
    /// Gateway events). The body is parsed as [`DiscordInteraction`] and
    /// mapped onto the normalized event before ingestion.
    pub fn ingest_signed_interaction(
        &self,
        signature_hex: &str,
        timestamp: &str,
        body: &[u8],
        now_millis: i64,
    ) -> Result<SignedInteractionOutcome, IngestError> {
        verify_interaction_signature(
            &self.bot_config.application_public_key_hex,
            signature_hex,
            timestamp,
            body,
        )
        .map_err(|_| IngestError::SignatureVerificationFailed)?;
        // The timestamp is authenticated by the signature above; enforce
        // freshness so a captured webhook cannot be replayed after its
        // dedupe key expires.
        let timestamp_ms = parse_interaction_timestamp(timestamp, now_millis)?;
        let interaction: DiscordInteraction =
            serde_json::from_slice(body).map_err(|e| IngestError::MalformedEvent {
                reason: format!("not a discord interaction: {e}"),
            })?;
        match interaction.kind {
            // Discord endpoint validation: the host must answer `{"type":1}`;
            // there is nothing to ingest.
            1 => Ok(SignedInteractionOutcome::Ping),
            2..=5 => {
                let event = interaction.into_gateway_event(timestamp_ms)?;
                self.ingest_event(body, &event, now_millis)
                    .map(|envelope| SignedInteractionOutcome::Event(envelope.map(Box::new)))
            }
            other => Err(IngestError::MalformedEvent {
                reason: format!("unsupported interaction type {other}"),
            }),
        }
    }

    /// Builds the exact Discord REST call for an outbound request. The host
    /// executes it with the kernel-brokered bot token.
    pub fn build_rest_call(
        &self,
        request: &OutboundRequest,
    ) -> Result<DiscordRestCall, DiscordError> {
        if request.provider != Provider::Discord {
            return Err(DiscordError::WrongProvider);
        }
        let channel_id = self.outbound_channel_id(&request.target)?;
        // Discord rejects empty content (error 50006) after the host has
        // already run authorization and audit: fail here instead.
        let text = match request.verb {
            OutboundVerb::Send | OutboundVerb::Edit => request
                .text
                .clone()
                .filter(|t| !t.is_empty())
                .ok_or(DiscordError::MissingText)?,
            _ => String::new(),
        };
        match request.verb {
            OutboundVerb::Send => Ok(DiscordRestCall::post_channel_message(&channel_id, &text)),
            OutboundVerb::Edit => {
                let message_id = request
                    .target_message_id
                    .as_ref()
                    .ok_or(DiscordError::MissingTargetMessage)?;
                let message_id = snowflake(message_id.as_str())?;
                Ok(DiscordRestCall {
                    method: "PATCH",
                    url: format!(
                        "https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}"
                    ),
                    body_json: serde_json::json!({ "content": text }).to_string(),
                })
            }
            OutboundVerb::React => {
                let message_id = request
                    .target_message_id
                    .as_ref()
                    .ok_or(DiscordError::MissingTargetMessage)?;
                let message_id = snowflake(message_id.as_str())?;
                let reaction = request
                    .reaction
                    .as_deref()
                    .ok_or(DiscordError::MissingReaction)?;
                let encoded = url_encode(reaction);
                Ok(DiscordRestCall {
                    method: "PUT",
                    url: format!(
                        "https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}/reactions/{encoded}/@me"
                    ),
                    body_json: String::new(),
                })
            }
            OutboundVerb::Delete => {
                let message_id = request
                    .target_message_id
                    .as_ref()
                    .ok_or(DiscordError::MissingTargetMessage)?;
                let message_id = snowflake(message_id.as_str())?;
                Ok(DiscordRestCall {
                    method: "DELETE",
                    url: format!(
                        "https://discord.com/api/v10/channels/{channel_id}/messages/{message_id}"
                    ),
                    body_json: String::new(),
                })
            }
            OutboundVerb::Moderate | OutboundVerb::Upload => Err(DiscordError::VerbNotMapped),
        }
    }

    fn outbound_channel_id(&self, target: &OutboundTarget) -> Result<String, DiscordError> {
        match target {
            OutboundTarget::Conversation(conversation) => {
                Ok(snowflake(&conversation.channel_id)?.to_owned())
            }
            OutboundTarget::DirectRecipient { .. } => Err(DiscordError::DmNeedsChannel),
        }
    }

    fn check_allowlist(&self, event: &DiscordGatewayEvent) -> Result<(), IngestError> {
        if let Some(guild_id) = &event.guild_id {
            if !self.bot_config.allowed_guilds.is_empty()
                && !self.bot_config.allowed_guilds.iter().any(|g| g == guild_id)
            {
                return Err(IngestError::MalformedEvent {
                    reason: "guild not in allowlist".to_owned(),
                });
            }
        } else if !self.bot_config.allow_dms {
            return Err(IngestError::MalformedEvent {
                reason: "DMs not enabled".to_owned(),
            });
        }
        if !self.bot_config.allowed_channels.is_empty()
            && !self
                .bot_config
                .allowed_channels
                .iter()
                .any(|c| c == &event.channel_id)
        {
            return Err(IngestError::MalformedEvent {
                reason: "channel not in allowlist".to_owned(),
            });
        }
        Ok(())
    }

    fn ingest_event(
        &self,
        raw_event: &[u8],
        event: &DiscordGatewayEvent,
        now_millis: i64,
    ) -> Result<Option<MessageEnvelope>, IngestError> {
        if !matches!(self.state, ConnectionState::Bound) {
            return Err(IngestError::AdapterDisabled);
        }
        self.check_allowlist(event)?;

        let connection_id = self
            .binding
            .as_ref()
            .ok_or(IngestError::AuthLost {
                reason: "no connection binding".to_owned(),
            })?
            .connection_id
            .clone();

        let message_id = ProviderMessageId::new(event.message_id.clone()).map_err(|e| {
            IngestError::MalformedEvent {
                reason: e.to_string(),
            }
        })?;

        let dedupe_key = DedupeKey::compute(Provider::Discord, &connection_id, &message_id);
        // Explicit principal mapping; fail closed on ambiguity or absence.
        // Pure lookup, so it runs BEFORE the dedupe insert: a message
        // rejected here must not record a dedupe key, otherwise a redelivery
        // after the operator maps the identity would collapse to Skip.
        let resolution = self.registry.resolve(Provider::Discord, &event.author_id);
        match resolution {
            PrincipalResolution::Ambiguous => return Err(IngestError::AmbiguousIdentity),
            PrincipalResolution::Unknown => return Err(IngestError::UnknownIdentity),
            PrincipalResolution::Mapped(_) => {}
        }
        match DedupeDecision::decide(self.dedupe.check_and_insert(&dedupe_key))? {
            DedupeDecision::Proceed => {}
            // Known redelivery: the first delivery already entered the
            // pipeline. Skip without disturbing the batch.
            DedupeDecision::Skip => return Ok(None),
        }

        let mut conversation = Conversation::channel(event.channel_id.clone()).map_err(|e| {
            IngestError::MalformedEvent {
                reason: e.to_string(),
            }
        })?;
        conversation.server_id = event.guild_id.clone();
        conversation.thread_id = event.thread_id.clone();
        if event.guild_id.is_none() {
            conversation.direct_peer = Some(event.author_id.clone());
        }

        let mut sender = SenderIdentity::new(event.author_id.clone(), resolution.verification())
            .map_err(|e| IngestError::MalformedEvent {
                reason: e.to_string(),
            })?;
        if let Some(name) = &event.author_name {
            sender = sender.with_display_name(name.clone());
        }

        let reply_context = ReplyContext {
            quotes_message_id: event.reply_to_message_id.clone(),
            ..Default::default()
        };

        let provenance = Provenance::new("discord", ADAPTER_VERSION, raw_event).map_err(|e| {
            IngestError::MalformedEvent {
                reason: e.to_string(),
            }
        })?;

        Ok(Some(
            MessageEnvelope::new(
                Provider::Discord,
                connection_id,
                conversation,
                sender,
                message_id,
                event.content.clone(),
                Vec::new(),
                reply_context,
                event.timestamp_ms,
                provenance,
                TransportTrust::ProviderTerminated,
                now_millis,
            )
            .map_err(|e| IngestError::MalformedEvent {
                reason: e.to_string(),
            })?,
        ))
    }
}

/// Validates a Discord snowflake id before it is interpolated into a REST
/// path. Discord ids are unsigned 64-bit integers in decimal; anything else
/// (including `/` or `..` segments, which the envelope's generic identifier
/// check permits) is rejected so a crafted id can never escape the intended
/// channel/message path when a host executor normalizes dot segments.
fn snowflake(id: &str) -> Result<&str, DiscordError> {
    if !id.is_empty() && id.len() <= 20 && id.bytes().all(|b| b.is_ascii_digit()) {
        Ok(id)
    } else {
        Err(DiscordError::InvalidId)
    }
}

fn url_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[async_trait]
impl MessagingAdapter for DiscordAdapter {
    fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    fn descriptor_provider(&self) -> Provider {
        Provider::Discord
    }

    fn state(&self) -> ConnectionState {
        self.state.clone()
    }

    fn bound_connection_id(&self) -> Option<&ConnectionId> {
        self.binding.as_ref().map(|b| &b.connection_id)
    }

    async fn bind(
        &mut self,
        binding: ConnectionBinding,
        config: &MessagingConfig,
    ) -> Result<(), AdapterError> {
        // Double gate: Cargo feature (compile time) + runtime flag.
        if !config.discord_enabled {
            return Err(AdapterError::Disabled);
        }
        self.binding = Some(binding);
        self.state = ConnectionState::Bound;
        Ok(())
    }

    fn revoke(&mut self) {
        self.binding = None;
        self.state = ConnectionState::Revoked {
            reason: "operator revoked the Discord connection".to_owned(),
        };
    }

    fn ingest(
        &self,
        raw_event: &[u8],
        now_millis: i64,
    ) -> Result<Option<MessageEnvelope>, IngestError> {
        // Raw events are host-normalized gateway events from an already
        // authenticated Gateway session. Interaction webhooks must go through
        // `ingest_signed_interaction` instead.
        let event: DiscordGatewayEvent =
            serde_json::from_slice(raw_event).map_err(|e| IngestError::MalformedEvent {
                reason: format!("not a discord gateway event: {e}"),
            })?;
        self.ingest_event(raw_event, &event, now_millis)
    }

    async fn execute_outbound(
        &self,
        _request: &OutboundRequest,
    ) -> Result<ProviderReceipt, AdapterError> {
        // Beta scaffolding: the adapter builds the exact REST call but never
        // touches the network or the bot token. The host executes
        // `build_rest_call` with the kernel-brokered credential and records
        // the receipt itself. Failing closed here is deliberate.
        self.transport_check()?;
        Err(AdapterError::Transport {
            reason: "discord beta: outbound executes via the host REST executor; use build_rest_call with the kernel-brokered bot token".to_owned(),
        })
    }
}

impl DiscordAdapter {
    fn transport_check(&self) -> Result<(), AdapterError> {
        if !matches!(self.state, ConnectionState::Bound) {
            return Err(AdapterError::NotBound);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DiscordError {
    #[error("bad application public key")]
    BadPublicKey,
    #[error("interaction signature verification failed")]
    BadSignature,
    #[error("invalid discord config: {0}")]
    InvalidConfig(&'static str),
    #[error("request is not for the discord provider")]
    WrongProvider,
    #[error("verb has no discord REST mapping")]
    VerbNotMapped,
    #[error("edit/react/delete require target_message_id")]
    MissingTargetMessage,
    #[error("react requires a reaction")]
    MissingReaction,
    #[error("DM sends need an open DM channel id; use a conversation target")]
    DmNeedsChannel,
    #[error("invalid discord snowflake id")]
    InvalidId,
    #[error("send/edit requires non-empty text")]
    MissingText,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dedupe::MemoryDedupeStore;
    use crate::envelope::ConnectionId;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Test vector generated for these tests (ChaCha8 seeded with 0xC10C).
    const TEST_PUBLIC_KEY: &str =
        "6b183debb2bf20f37779e89da5a3c414cd6b4329b6ff6a98b6154bd26b9df33d";
    const TEST_SECRET_KEY: &str =
        "1504beec3a1122c9794733e937b6b9bc0c0197ce1a713af0bb669ab7a03503ad";

    fn now_millis() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    fn test_config() -> DiscordBotConfig {
        DiscordBotConfig {
            application_id: "123".to_owned(),
            application_public_key_hex: TEST_PUBLIC_KEY.to_owned(),
            token_handle: CredentialHandle::new("handle-discord").unwrap(),
            allowed_guilds: vec![],
            allowed_channels: vec![],
            allow_dms: true,
            intents: DiscordIntents::minimum(),
        }
    }

    fn test_adapter() -> DiscordAdapter {
        let mut registry = PrincipalMappingRegistry::new();
        registry
            .register(
                Provider::Discord,
                "user-1",
                lumen_core::identity::PrincipalId::new("bct", "user1").unwrap(),
            )
            .unwrap();
        let mut adapter = DiscordAdapter::new(
            test_config(),
            Arc::new(registry),
            Arc::new(MemoryDedupeStore::new(60_000)),
        )
        .unwrap();
        adapter.state = ConnectionState::Bound;
        adapter.binding = Some(
            ConnectionBinding::new(
                ConnectionId::new("conn-discord").unwrap(),
                "bct-account",
                CredentialHandle::new("handle-discord").unwrap(),
            )
            .unwrap(),
        );
        adapter
    }

    fn gateway_event_json() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "kind": "message",
            "guild_id": null,
            "channel_id": "dm-chan-1",
            "author_id": "user-1",
            "author_name": "Alice",
            "message_id": "msg-1",
            "content": "hello from discord",
            "timestamp_ms": now_millis(),
        }))
        .unwrap()
    }

    #[test]
    fn interaction_signature_verification_is_real() {
        use ed25519_dalek::{Signer, SigningKey};
        let secret: [u8; 32] = hex::decode(TEST_SECRET_KEY).unwrap().try_into().unwrap();
        let signing = SigningKey::from_bytes(&secret);
        assert_eq!(
            hex::encode(signing.verifying_key().to_bytes()),
            TEST_PUBLIC_KEY
        );

        let timestamp = "1234567890";
        let body = br#"{"type":1}"#;
        let mut msg = Vec::new();
        msg.extend_from_slice(timestamp.as_bytes());
        msg.extend_from_slice(body);
        let signature = signing.sign(&msg);

        // Valid signature verifies.
        assert!(
            verify_interaction_signature(
                TEST_PUBLIC_KEY,
                &hex::encode(signature.to_bytes()),
                timestamp,
                body,
            )
            .is_ok()
        );
        // Wrong timestamp fails.
        assert_eq!(
            verify_interaction_signature(
                TEST_PUBLIC_KEY,
                &hex::encode(signature.to_bytes()),
                "9999999999",
                body,
            )
            .unwrap_err(),
            DiscordError::BadSignature
        );
        // Tampered body fails.
        assert!(
            verify_interaction_signature(
                TEST_PUBLIC_KEY,
                &hex::encode(signature.to_bytes()),
                timestamp,
                br#"{"type":2}"#,
            )
            .is_err()
        );
        // Wrong key fails.
        assert!(
            verify_interaction_signature(
                &"00".repeat(32),
                &hex::encode(signature.to_bytes()),
                timestamp,
                body,
            )
            .is_err()
        );
    }

    fn sign_interaction(timestamp: &str, body: &[u8]) -> String {
        use ed25519_dalek::{Signer, SigningKey};
        let secret: [u8; 32] = hex::decode(TEST_SECRET_KEY).unwrap().try_into().unwrap();
        let signing = SigningKey::from_bytes(&secret);
        let mut msg = Vec::new();
        msg.extend_from_slice(timestamp.as_bytes());
        msg.extend_from_slice(body);
        hex::encode(signing.sign(&msg).to_bytes())
    }

    fn interaction_test_adapter(author_id: &str) -> DiscordAdapter {
        let mut registry = PrincipalMappingRegistry::new();
        registry
            .register(
                Provider::Discord,
                author_id,
                lumen_core::identity::PrincipalId::new("bct", "user1").unwrap(),
            )
            .unwrap();
        let mut adapter = DiscordAdapter::new(
            test_config(),
            Arc::new(registry),
            Arc::new(MemoryDedupeStore::new(3_600_000)),
        )
        .unwrap();
        adapter.state = ConnectionState::Bound;
        adapter.binding = Some(
            ConnectionBinding::new(
                ConnectionId::new("conn-discord").unwrap(),
                "bct-account",
                CredentialHandle::new("handle-discord").unwrap(),
            )
            .unwrap(),
        );
        adapter
    }

    fn fresh_timestamp_secs() -> String {
        (now_millis() / 1000).to_string()
    }

    #[test]
    fn signed_interaction_ingests_real_payload() {
        let author_id = "333333333333333333";
        let adapter = interaction_test_adapter(author_id);
        let timestamp = fresh_timestamp_secs();
        let body = serde_json::to_vec(&serde_json::json!({
            "type": 2,
            "id": "123456789012345679",
            "application_id": "123456789012345670",
            "guild_id": "111111111111111111",
            "channel_id": "222222222222222222",
            "member": {
                "user": {
                    "id": author_id,
                    "username": "alice",
                    "global_name": "Alice",
                },
                "nick": "Ali",
            },
            "data": {"name": "deploy", "type": 1},
            "token": "interaction-token",
            "version": 1,
        }))
        .unwrap();
        let signature = sign_interaction(&timestamp, &body);

        let outcome = adapter
            .ingest_signed_interaction(&signature, &timestamp, &body, now_millis())
            .expect("signed interaction ingests");
        let envelope = match outcome {
            SignedInteractionOutcome::Event(Some(envelope)) => envelope,
            other => panic!("expected an ingested event, got {other:?}"),
        };
        assert_eq!(envelope.provider, Provider::Discord);
        assert_eq!(envelope.message_id.as_str(), "123456789012345679");
        assert_eq!(envelope.sender.external_id, author_id);
        assert_eq!(envelope.sender.display_name.as_deref(), Some("Ali"));
        assert_eq!(envelope.content, "/deploy");
        assert_eq!(envelope.conversation.channel_id, "222222222222222222");
        assert_eq!(
            envelope.conversation.server_id.as_deref(),
            Some("111111111111111111")
        );
        assert!(envelope.sender_is_verified());

        // Redelivery of the same interaction collapses to None.
        let outcome = adapter
            .ingest_signed_interaction(&signature, &timestamp, &body, now_millis())
            .expect("redelivery ingests");
        assert!(matches!(outcome, SignedInteractionOutcome::Event(None)));
    }

    #[test]
    fn signed_interaction_ping_returns_ping_outcome() {
        let adapter = interaction_test_adapter("333333333333333333");
        let timestamp = fresh_timestamp_secs();
        let body = br#"{"type":1,"id":"1"}"#;
        let signature = sign_interaction(&timestamp, body);

        let outcome = adapter
            .ingest_signed_interaction(&signature, &timestamp, body, now_millis())
            .expect("ping ingests");
        assert!(matches!(outcome, SignedInteractionOutcome::Ping));
    }

    #[test]
    fn signed_interaction_rejects_stale_timestamp() {
        let adapter = interaction_test_adapter("333333333333333333");
        // An hour old: well outside the freshness window.
        let timestamp = (now_millis() / 1000 - 3600).to_string();
        let body = br#"{"type":1,"id":"1"}"#;
        let signature = sign_interaction(&timestamp, body);

        let err = adapter
            .ingest_signed_interaction(&signature, &timestamp, body, now_millis())
            .unwrap_err();
        assert!(
            matches!(err, IngestError::MalformedEvent { .. }),
            "expected MalformedEvent, got {err:?}"
        );
    }

    #[test]
    fn signed_interaction_rejects_tampered_body() {
        let adapter = interaction_test_adapter("333333333333333333");
        let timestamp = fresh_timestamp_secs();
        let body = br#"{"type":2,"id":"123456789012345679"}"#;
        let signature = sign_interaction(&timestamp, body);
        let tampered = br#"{"type":2,"id":"999999999999999999"}"#;

        let err = adapter
            .ingest_signed_interaction(&signature, &timestamp, tampered, now_millis())
            .unwrap_err();
        assert_eq!(err, IngestError::SignatureVerificationFailed);
    }

    #[test]
    fn bind_requires_the_runtime_flag() {
        let mut adapter = DiscordAdapter::new(
            test_config(),
            Arc::new(PrincipalMappingRegistry::new()),
            Arc::new(MemoryDedupeStore::new(60_000)),
        )
        .unwrap();
        let binding = ConnectionBinding::new(
            ConnectionId::new("c").unwrap(),
            "bct",
            CredentialHandle::new("h").unwrap(),
        )
        .unwrap();
        let config = MessagingConfig::default(); // discord_enabled = false
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(adapter.bind(binding, &config));
        assert_eq!(result.unwrap_err(), AdapterError::Disabled);
    }

    #[test]
    fn ingest_dm_envelope() {
        let adapter = test_adapter();
        let raw = gateway_event_json();
        let env = adapter
            .ingest(&raw, now_millis())
            .unwrap()
            .expect("first delivery ingests");
        assert_eq!(env.provider, Provider::Discord);
        assert_eq!(env.content, "hello from discord");
        assert!(env.sender_is_verified());
        // Discord transport is not E2E to Lumen.
        assert!(env.transport_is_untrusted());
        assert_eq!(env.conversation.direct_peer.as_deref(), Some("user-1"));

        // Duplicate collapses to None.
        assert_eq!(adapter.ingest(&raw, now_millis()).unwrap(), None);
    }

    #[test]
    fn allowlist_fails_closed() {
        let mut config = test_config();
        config.allowed_channels = vec!["other-chan".to_owned()];
        let mut adapter = DiscordAdapter::new(
            config,
            Arc::new(PrincipalMappingRegistry::new()),
            Arc::new(MemoryDedupeStore::new(60_000)),
        )
        .unwrap();
        adapter.state = ConnectionState::Bound;
        adapter.binding = Some(
            ConnectionBinding::new(
                ConnectionId::new("c").unwrap(),
                "bct",
                CredentialHandle::new("h").unwrap(),
            )
            .unwrap(),
        );
        let err = adapter
            .ingest(&gateway_event_json(), now_millis())
            .unwrap_err();
        assert!(matches!(err, IngestError::MalformedEvent { .. }));
    }

    #[test]
    fn rest_call_shapes_are_exact() {
        let adapter = test_adapter();
        let mut request = crate::outbound::test_support::test_request(OutboundVerb::Send);
        request.provider = Provider::Discord;
        request.target =
            OutboundTarget::Conversation(Conversation::channel("123456789012345678").unwrap());
        let call = adapter.build_rest_call(&request).unwrap();
        assert_eq!(call.method, "POST");
        assert_eq!(
            call.url,
            "https://discord.com/api/v10/channels/123456789012345678/messages"
        );
        assert!(call.body_json.contains("hello"));

        request.verb = OutboundVerb::Delete;
        request.target_message_id = Some(ProviderMessageId::new("987654321098765432").unwrap());
        let call = adapter.build_rest_call(&request).unwrap();
        assert_eq!(call.method, "DELETE");
        assert!(
            call.url
                .ends_with("/channels/123456789012345678/messages/987654321098765432")
        );

        request.verb = OutboundVerb::Upload;
        assert_eq!(
            adapter.build_rest_call(&request).unwrap_err(),
            DiscordError::VerbNotMapped
        );
    }

    #[test]
    fn rest_call_rejects_non_snowflake_ids() {
        let adapter = test_adapter();
        let mut request = crate::outbound::test_support::test_request(OutboundVerb::Send);
        request.provider = Provider::Discord;
        // Path traversal in the channel id must not reach the URL.
        request.target = OutboundTarget::Conversation(Conversation::channel("123/../456").unwrap());
        assert_eq!(
            adapter.build_rest_call(&request).unwrap_err(),
            DiscordError::InvalidId
        );

        request.target =
            OutboundTarget::Conversation(Conversation::channel("123456789012345678").unwrap());
        request.verb = OutboundVerb::Delete;
        request.target_message_id = Some(ProviderMessageId::new("../../x").unwrap());
        assert_eq!(
            adapter.build_rest_call(&request).unwrap_err(),
            DiscordError::InvalidId
        );
    }

    #[test]
    fn rest_call_rejects_empty_text_for_send_and_edit() {
        let adapter = test_adapter();
        let mut request = crate::outbound::test_support::test_request(OutboundVerb::Send);
        request.provider = Provider::Discord;
        request.target =
            OutboundTarget::Conversation(Conversation::channel("123456789012345678").unwrap());
        request.text = None;
        assert_eq!(
            adapter.build_rest_call(&request).unwrap_err(),
            DiscordError::MissingText
        );
        request.text = Some(String::new());
        assert_eq!(
            adapter.build_rest_call(&request).unwrap_err(),
            DiscordError::MissingText
        );

        // Other verbs do not need text.
        request.verb = OutboundVerb::Delete;
        request.target_message_id = Some(ProviderMessageId::new("987654321098765432").unwrap());
        assert!(adapter.build_rest_call(&request).is_ok());
    }

    #[test]
    fn minimum_intents_request_nothing_privileged() {
        assert!(!DiscordIntents::minimum().requests_privileged());
        let mut intents = DiscordIntents::minimum();
        intents.message_content = true;
        assert!(intents.requests_privileged());
    }

    #[test]
    fn bad_public_key_rejected_at_construction() {
        let mut config = test_config();
        config.application_public_key_hex = "not-hex".to_owned();
        assert!(
            DiscordAdapter::new(
                config,
                Arc::new(PrincipalMappingRegistry::new()),
                Arc::new(MemoryDedupeStore::new(60_000)),
            )
            .is_err()
        );
    }
}
