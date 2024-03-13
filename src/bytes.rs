use serde::{de::Visitor, Deserialize};

#[derive(Clone, Debug)]
pub struct Bytes(Vec<u8>);

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str(
            "a variable-length byte array represented by a raw byte array or a hex-encoded string",
        )
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let v = v.strip_prefix("0x").unwrap_or(v);
        let v = hex::decode(v).map_err(E::custom)?;
        Ok(v)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let v = hex::decode(v).map_err(E::custom)?;
        Ok(v)
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(BytesVisitor).map(Bytes)
        } else {
            deserializer.deserialize_bytes(BytesVisitor).map(Bytes)
        }
    }
}
