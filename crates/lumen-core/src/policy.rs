use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{
    action::ActionEnvelope,
    capability::{Capability, CapabilityName, EffectiveCapabilities},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny(DenialReason),
    RequireApproval,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DenialReason {
    NoCapabilitiesDeclared,
    MissingCapability(Capability),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Policy {
    approval_required: BTreeSet<CapabilityName>,
}

impl Policy {
    pub fn evaluate(
        &self,
        action: &ActionEnvelope,
        capabilities: &EffectiveCapabilities,
    ) -> PolicyDecision {
        if action.required_capabilities().is_empty() {
            return PolicyDecision::Deny(DenialReason::NoCapabilitiesDeclared);
        }

        for required in action.required_capabilities() {
            if !capabilities.allows(required) {
                return PolicyDecision::Deny(DenialReason::MissingCapability(required.clone()));
            }
        }

        if action
            .required_capabilities()
            .iter()
            .any(|capability| self.approval_required.contains(&capability.name()))
        {
            PolicyDecision::RequireApproval
        } else {
            PolicyDecision::Allow
        }
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            approval_required: [
                CapabilityName::FsWrite,
                CapabilityName::FsDelete,
                CapabilityName::ProcessSpawn,
                CapabilityName::NetConnect,
                CapabilityName::SecretUse,
                CapabilityName::MessageSend,
                CapabilityName::ScheduleCreate,
                CapabilityName::ScheduleModify,
                CapabilityName::PluginInstall,
                CapabilityName::PluginUpdate,
                CapabilityName::PluginEnable,
                CapabilityName::PolicyModify,
            ]
            .into_iter()
            .collect(),
        }
    }
}
