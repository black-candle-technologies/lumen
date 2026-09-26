//! Signed-resource decoding validates without repairing or dropping authority.
use super::*;
use serde::{
    Deserializer,
    de::{self, MapAccess, Visitor},
};
use std::marker::PhantomData;

macro_rules! validated_string {
    ($type:ty) => {
        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::parse(&raw).map_err(de::Error::custom)
            }
        }
    };
}
validated_string!(ToolName);
validated_string!(SecretRef);

/// Serde's ordinary map decoder overwrites duplicate keys. Never use that
/// behavior for authority maps, including nested provider grants.
pub(crate) fn unique_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    struct Unique<K, V>(PhantomData<(K, V)>);
    impl<'de, K: Deserialize<'de> + Ord, V: Deserialize<'de>> Visitor<'de> for Unique<K, V> {
        type Value = BTreeMap<K, V>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("unique authority keys")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = input.next_entry()? {
                if out.insert(key, value).is_some() {
                    return Err(de::Error::custom("duplicate authority key"));
                }
            }
            Ok(out)
        }
    }
    deserializer.deserialize_map(Unique(PhantomData))
}

impl CanonicalPath {
    pub(super) fn validate(&self) -> Result<(), CanonicalError> {
        if self.absolute_path().len() > 4096
            || self.components.iter().any(|s| {
                s.is_empty()
                    || s == "."
                    || s == ".."
                    || s.contains('/')
                    || s.chars().any(|c| c == '\0' || c.is_control())
                    || (self.case_folded && s.to_lowercase() != *s)
            })
        {
            return Err(CanonicalError::InvalidEncoding(
                "path components or filesystem view",
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CanonicalPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            components: Vec<String>,
            case_folded: bool,
        }
        let raw = Wire::deserialize(deserializer)?;
        let value = Self {
            components: raw.components,
            case_folded: raw.case_folded,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

impl HostPattern {
    pub(super) fn validate(&self) -> Result<(), CanonicalError> {
        let parsed = match self {
            Self::DnsName(name) => Self::parse(name)?,
            Self::DnsWildcard(suffix) => Self::parse(&format!("*.{suffix}"))?,
            Self::Ip(_) => return Ok(()),
            Self::IpRange(net) => Self::parse(&net.to_string())?,
        };
        if parsed != *self {
            return Err(CanonicalError::InvalidEncoding(
                "host must already be canonical",
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for HostPattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        enum Wire {
            DnsName(String),
            DnsWildcard(String),
            Ip(IpAddr),
            IpRange(IpNet),
        }
        let value = match Wire::deserialize(deserializer)? {
            Wire::DnsName(v) => Self::DnsName(v),
            Wire::DnsWildcard(v) => Self::DnsWildcard(v),
            Wire::Ip(v) => Self::Ip(v),
            Wire::IpRange(v) => Self::IpRange(v),
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

impl PortSet {
    pub(super) fn validate(&self) -> Result<(), CanonicalError> {
        if self.any {
            if !self.ranges.is_empty() {
                return Err(CanonicalError::InvalidEncoding(
                    "any ports cannot contain ranges",
                ));
            }
        } else if Self::from_ranges(&self.ranges)? != *self {
            return Err(CanonicalError::InvalidEncoding(
                "port ranges must already be normalized",
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for PortSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            ranges: Vec<(u16, u16)>,
            any: bool,
        }
        let raw = Wire::deserialize(deserializer)?;
        let value = Self {
            ranges: raw.ranges,
            any: raw.any,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

impl NetworkDestination {
    pub(super) fn validate(&self) -> Result<(), CanonicalError> {
        self.host.validate()?;
        self.ports.validate()?;
        if !self.scheme.is_empty() {
            let mut bytes = self.scheme.bytes();
            if !bytes.next().is_some_and(|b| b.is_ascii_lowercase())
                || !bytes
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+-.".contains(&b))
            {
                return Err(CanonicalError::InvalidEncoding("scheme"));
            }
        }
        if self
            .methods
            .iter()
            .any(|m| m.is_empty() || !Self::is_canonical_method(m))
            || (!self.methods_apply() && !self.methods.is_empty())
        {
            return Err(CanonicalError::InvalidEncoding("method scope"));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for NetworkDestination {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            scheme: String,
            host: HostPattern,
            ports: PortSet,
            methods: BTreeSet<String>,
        }
        let raw = Wire::deserialize(deserializer)?;
        let value = Self {
            scheme: raw.scheme,
            host: raw.host,
            ports: raw.ports,
            methods: raw.methods,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for AccountRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            provider: String,
            account_id: String,
        }
        let raw = Wire::deserialize(deserializer)?;
        let value = Self::parse(&raw.provider, &raw.account_id).map_err(de::Error::custom)?;
        if value.provider != raw.provider {
            return Err(de::Error::custom(
                "account provider must already be canonical",
            ));
        }
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for ModelClass {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            provider: String,
            class: String,
        }
        let raw = Wire::deserialize(deserializer)?;
        Self::parse(&raw.provider, &raw.class).map_err(de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for ResourceScope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize, Default)]
        #[serde(deny_unknown_fields, default)]
        struct Wire {
            #[serde(deserialize_with = "unique_map")]
            tools: BTreeMap<String, VersionReq>,
            paths: Vec<PathGrant>,
            destinations: Vec<NetworkDestination>,
            secrets: BTreeSet<String>,
            accounts: BTreeSet<AccountRef>,
            #[serde(deserialize_with = "unique_map")]
            models: BTreeMap<String, BTreeSet<String>>,
            effects: Vec<EffectClass>,
        }
        let raw = Wire::deserialize(deserializer)?;
        let value = Self {
            tools: raw.tools,
            paths: raw.paths,
            destinations: raw.destinations,
            secrets: raw.secrets,
            accounts: raw.accounts,
            models: raw.models,
            effects: raw.effects,
        };
        value.validate().map_err(de::Error::custom)?;
        Ok(value)
    }
}
