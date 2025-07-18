mod master;
mod rights;
mod tracing;
mod user;

use crate::policy::{AccessStructure, RevisionMap, Right};

/// Number of colluding users needed to escape tracing.
pub const MIN_TRACING_LEVEL: usize = 1;

/// The length of the key used to sign user secret keys.
///
/// It is only 16-byte long because no post-quantum security is needed for
/// now. An upgraded signature scheme can still be added later when quantum
/// computers become available.
const SIGNING_KEY_LENGTH: usize = 16;

/// The length of the KMAC signature.
const SIGNATURE_LENGTH: usize = 32;

/// KMAC signature is used to guarantee the integrity of the user secret keys.
type KmacSignature = [u8; SIGNATURE_LENGTH];
