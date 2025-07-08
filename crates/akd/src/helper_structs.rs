//! Forked Code from Meta Platforms AKD repository: https://github.com/facebook/akd
//! Helper structs that are used for various data structures,
//! to make it easier to pass arguments around.

use crate::Digest;
use crate::{NodeLabel, storage::types::ValueState};

/// Root hash of the tree and its associated epoch
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EpochHash(pub u64, pub Digest);

impl EpochHash {
    /// Get the contained epoch
    pub fn epoch(&self) -> u64 {
        self.0
    }
    /// Get the contained hash
    pub fn hash(&self) -> Digest {
        self.1
    }
}

#[derive(Clone, Debug)]
/// Info needed for a lookup of a user for an epoch
pub struct LookupInfo {
    pub(crate) value_state: ValueState,
    pub(crate) marker_version: u64,
    pub(crate) existent_label: NodeLabel,
    pub(crate) marker_label: NodeLabel,
    pub(crate) non_existent_label: NodeLabel,
}
