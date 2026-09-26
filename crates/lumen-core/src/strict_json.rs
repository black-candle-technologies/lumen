//! Authority JSON decoding before object keys or number representations can
//! be lost. Call at the first raw-wire boundary, not after parsing a Value.
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::{collections::BTreeMap, fmt};

struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        value(decoder).map(Self)
    }
}

/// JSON values with integer-only numbers and recursively unique object keys.
pub fn value<'de, D: Deserializer<'de>>(decoder: D) -> Result<Value, D::Error> {
    struct Strict;
    impl<'de> Visitor<'de> for Strict {
        type Value = Value;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("integer-only JSON with unique keys")
        }
        fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_none<E: de::Error>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
            Ok(Value::Bool(v))
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
            Ok(Value::Number(Number::from(v)))
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
            Ok(Value::Number(Number::from(v)))
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<Value, E> {
            Err(E::custom("non-integer authority number"))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
            Ok(Value::String(v.into()))
        }
        fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
            Ok(Value::String(v))
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
            let mut values = Vec::new();
            while let Some(StrictValue(v)) = input.next_element()? {
                values.push(v);
            }
            Ok(Value::Array(values))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
            let mut values = Map::new();
            while let Some((key, StrictValue(v))) = input.next_entry::<String, StrictValue>()? {
                if values.insert(key, v).is_some() {
                    return Err(de::Error::custom("duplicate authority object key"));
                }
            }
            Ok(Value::Object(values))
        }
    }
    decoder.deserialize_any(Strict)
}

/// The action argument root must be an object; nested values use the same
/// strict decoder, including objects inside arrays.
pub fn arguments<'de, D: Deserializer<'de>>(
    decoder: D,
) -> Result<BTreeMap<String, Value>, D::Error> {
    match value(decoder)? {
        Value::Object(map) => Ok(map.into_iter().collect()),
        _ => Err(de::Error::custom("authority arguments must be an object")),
    }
}

/// Object-root variant for host views that retain a JSON Value until the
/// kernel converts the payload into its typed argument map.
pub fn object<'de, D: Deserializer<'de>>(decoder: D) -> Result<Value, D::Error> {
    arguments(decoder).map(|values| Value::Object(values.into_iter().collect()))
}
