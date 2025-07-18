mod cryptography;
mod encryptedheader;
pub mod keys;

#[cfg(test)]
mod tests;

use crate::policy::Error;
use crate::{ElGamal, MlKem, SHARED_SECRET_LENGTH, kem::Kem, nike::Nike};
pub use keys::*;
use std::{collections::LinkedList, hash::Hash};

/// Length of the Covercrypt early abort tag. 128 bits are enough since we only want collision
/// resistance.
const TAG_LENGTH: usize = 16;

/// Covercrypt early abort tag is used during the decapsulation to verify the
/// integrity of the result.
type Tag = [u8; TAG_LENGTH];

/// Covercrypt user IDs are used to make user keys unique and traceable.
///
/// They are composed of a sequence of `LENGTH` scalars.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
struct UserId(LinkedList<<ElGamal as Nike>::SecretKey>);

impl UserId {
    /// Returns the tracing level of the USK.
    fn tracing_level(&self) -> usize {
        self.0.len() - 1
    }

    fn iter(&self) -> impl Iterator<Item = &<ElGamal as Nike>::SecretKey> {
        self.0.iter()
    }
}
