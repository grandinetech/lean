use serde::{Deserialize, Deserializer, Serializer, de::Error as SerdeError};

pub mod quoted_u64 {
    use super::{Deserialize, Deserializer, SerdeError, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value
            .parse::<u64>()
            .map_err(|err| SerdeError::custom(format!("invalid u64: {err}")))
    }
}
