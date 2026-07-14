use jsonschema::Validator;
use lumen_core::extension::Sha256Digest;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaLimits {
    max_schema_depth: usize,
    max_schema_bytes: usize,
    max_properties: usize,
    max_array_items: usize,
    max_string_bytes: usize,
    max_instance_bytes: usize,
}

impl SchemaLimits {
    pub const fn new(
        max_schema_depth: usize,
        max_schema_bytes: usize,
        max_properties: usize,
        max_array_items: usize,
        max_string_bytes: usize,
        max_instance_bytes: usize,
    ) -> Result<Self, SchemaError> {
        if max_schema_depth == 0
            || max_schema_bytes == 0
            || max_properties == 0
            || max_array_items == 0
            || max_string_bytes == 0
            || max_instance_bytes == 0
        {
            return Err(SchemaError::InvalidLimits);
        }
        Ok(Self {
            max_schema_depth,
            max_schema_bytes,
            max_properties,
            max_array_items,
            max_string_bytes,
            max_instance_bytes,
        })
    }
}

impl Default for SchemaLimits {
    fn default() -> Self {
        Self::new(16, 256 * 1024, 256, 1_024, 256 * 1024, 1024 * 1024)
            .expect("static schema limits")
    }
}

pub struct BoundedSchema {
    validator: Validator,
    limits: SchemaLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectiveSettings {
    value: Value,
    digest: Sha256Digest,
}

impl EffectiveSettings {
    pub const fn value(&self) -> &Value {
        &self.value
    }

    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

impl BoundedSchema {
    pub fn compile(schema: Value, limits: SchemaLimits) -> Result<Self, SchemaError> {
        let bytes = serde_json::to_vec(&schema).map_err(|_| SchemaError::InvalidSchema)?;
        if bytes.len() > limits.max_schema_bytes {
            return Err(SchemaError::SchemaTooLarge);
        }
        inspect_schema(&schema, 0, limits.max_schema_depth)?;
        let validator = jsonschema::validator_for(&schema)
            .map_err(|error| SchemaError::Compilation(error.to_string()))?;
        Ok(Self { validator, limits })
    }

    pub fn validate(&self, instance: &Value) -> Result<(), SchemaError> {
        let bytes = serde_json::to_vec(instance).map_err(|_| SchemaError::InvalidInstance)?;
        if bytes.len() > self.limits.max_instance_bytes {
            return Err(SchemaError::InstanceTooLarge);
        }
        inspect_instance(instance, 0, self.limits)?;
        self.validator
            .validate(instance)
            .map_err(|error| SchemaError::Validation(error.to_string()))
    }
}

pub fn merge_scoped_settings(
    schema: &BoundedSchema,
    layers: impl IntoIterator<Item = (u64, Value)>,
) -> Result<EffectiveSettings, SchemaError> {
    let mut effective = Value::Object(Default::default());
    let mut revisions = Vec::new();
    for (revision, layer) in layers {
        if !layer.is_object() {
            return Err(SchemaError::InvalidSettingsLayer);
        }
        merge_value(&mut effective, layer);
        revisions.push(revision);
    }
    schema.validate(&effective)?;
    let encoded = serde_json::to_vec(&serde_json::json!({
        "settings": &effective,
        "revisions": revisions,
    }))
    .map_err(|_| SchemaError::InvalidInstance)?;
    let digest = Sha256Digest::parse(format!("{:x}", Sha256::digest(encoded)))
        .expect("SHA-256 output is canonical");
    Ok(EffectiveSettings {
        value: effective,
        digest,
    })
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SchemaError {
    #[error("schema limits must all be greater than zero")]
    InvalidLimits,
    #[error("schema JSON is invalid")]
    InvalidSchema,
    #[error("schema exceeds the configured byte limit")]
    SchemaTooLarge,
    #[error("schema exceeds the configured depth limit")]
    SchemaTooDeep,
    #[error("schema keyword is unsupported: {0}")]
    UnsupportedKeyword(String),
    #[error("schema keyword has an unsupported value: {0}")]
    UnsupportedValue(String),
    #[error("schema compilation failed: {0}")]
    Compilation(String),
    #[error("instance JSON is invalid")]
    InvalidInstance,
    #[error("instance exceeds the configured byte limit")]
    InstanceTooLarge,
    #[error("instance exceeds a structural limit")]
    InstanceStructure,
    #[error("instance does not satisfy the schema: {0}")]
    Validation(String),
    #[error("each scoped settings layer must be a JSON object")]
    InvalidSettingsLayer,
}

fn merge_value(target: &mut Value, overlay: Value) {
    match (target, overlay) {
        (Value::Object(target), Value::Object(overlay)) => {
            for (key, value) in overlay {
                match target.get_mut(&key) {
                    Some(existing) if existing.is_object() && value.is_object() => {
                        merge_value(existing, value);
                    }
                    _ => {
                        target.insert(key, value);
                    }
                }
            }
        }
        (target, overlay) => *target = overlay,
    }
}

fn inspect_schema(value: &Value, depth: usize, max_depth: usize) -> Result<(), SchemaError> {
    if depth > max_depth {
        return Err(SchemaError::SchemaTooDeep);
    }
    let object = value
        .as_object()
        .ok_or_else(|| SchemaError::UnsupportedValue("schema must be an object".into()))?;
    for (keyword, value) in object {
        match keyword.as_str() {
            "$schema" | "title" | "description" => {
                if !value.is_string() {
                    return Err(SchemaError::UnsupportedValue(keyword.clone()));
                }
            }
            "type" => validate_type(value)?,
            "properties" => {
                let properties = value
                    .as_object()
                    .ok_or_else(|| SchemaError::UnsupportedValue(keyword.clone()))?;
                for schema in properties.values() {
                    inspect_schema(schema, depth + 1, max_depth)?;
                }
            }
            "items" => inspect_schema(value, depth + 1, max_depth)?,
            "additionalProperties" => {
                if !value.is_boolean() {
                    return Err(SchemaError::UnsupportedValue(keyword.clone()));
                }
            }
            "required" => {
                if !value
                    .as_array()
                    .is_some_and(|items| items.iter().all(Value::is_string))
                {
                    return Err(SchemaError::UnsupportedValue(keyword.clone()));
                }
            }
            "enum" => {
                if !value.is_array() {
                    return Err(SchemaError::UnsupportedValue(keyword.clone()));
                }
            }
            "const" | "default" => {}
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                if !value.is_number() {
                    return Err(SchemaError::UnsupportedValue(keyword.clone()));
                }
            }
            "minLength" | "maxLength" | "minItems" | "maxItems" | "minProperties"
            | "maxProperties" => {
                if !value.is_u64() {
                    return Err(SchemaError::UnsupportedValue(keyword.clone()));
                }
            }
            _ => return Err(SchemaError::UnsupportedKeyword(keyword.clone())),
        }
    }
    Ok(())
}

fn validate_type(value: &Value) -> Result<(), SchemaError> {
    const TYPES: [&str; 7] = [
        "null", "boolean", "object", "array", "number", "integer", "string",
    ];
    let valid = value.as_str().is_some_and(|value| TYPES.contains(&value));
    if valid {
        Ok(())
    } else {
        Err(SchemaError::UnsupportedValue("type".into()))
    }
}

fn inspect_instance(value: &Value, depth: usize, limits: SchemaLimits) -> Result<(), SchemaError> {
    if depth > limits.max_schema_depth {
        return Err(SchemaError::InstanceStructure);
    }
    match value {
        Value::String(value) if value.len() > limits.max_string_bytes => {
            Err(SchemaError::InstanceStructure)
        }
        Value::Array(values) => {
            if values.len() > limits.max_array_items {
                return Err(SchemaError::InstanceStructure);
            }
            for value in values {
                inspect_instance(value, depth + 1, limits)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > limits.max_properties {
                return Err(SchemaError::InstanceStructure);
            }
            for (key, value) in values {
                if key.len() > limits.max_string_bytes {
                    return Err(SchemaError::InstanceStructure);
                }
                inspect_instance(value, depth + 1, limits)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
