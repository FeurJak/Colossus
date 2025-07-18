use super::{
    SizeOf,
    serde_helpers::{bytes_deserialize_hex, bytes_serialize_hex},
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

/// The value of a particular entry in the AKD
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AkdValue(
    #[serde(serialize_with = "bytes_serialize_hex")]
    #[serde(deserialize_with = "bytes_deserialize_hex")]
    pub Vec<u8>,
);

impl SizeOf for AkdValue {
    fn size_of(&self) -> usize {
        self.0.len()
    }
}

impl core::ops::Deref for AkdValue {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for AkdValue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl core::convert::From<&str> for AkdValue {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl core::convert::From<&String> for AkdValue {
    fn from(s: &String) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl AkdValue {
    /// Gets a random value for a AKD
    pub fn random<R: CryptoRng + Rng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes.to_vec())
    }
}
