// Due to the amount of types an implementing storage layer needs to access,
// it's quite unreasonable to expose them all at the crate root, and a storage
// implementer will simply need to import the necessary inner types which are
// a dependency of ths [`Storage`] trait anyways
extern crate alloc;
extern crate rand;

pub mod append_only_zks;
pub mod auditor;
pub mod colossus;
pub mod directory;
pub mod helper_structs;
pub mod storage;
pub mod tree_node;
pub mod verify;
pub mod log {
    pub use tracing::{debug, error, info, trace, warn};
}
pub mod local_auditing;
pub use colossus::ColossusConfiguration;
pub use colossus_common::{
    ARITY,
    utils::{byte_arr_from_u64, get_marker_version_log2, get_marker_versions, i2osp_array},
};
pub use colossus_cryptography::{ecvrf, hash::rpx};
pub use colossus_types::*;

#[macro_use]
mod utils;

// ========== Type re-exports which are commonly used ========== //
pub use append_only_zks::{Azks, AzksParallelismConfig, AzksParallelismOption};
pub use directory::Directory;
pub use helper_structs::EpochHash;
pub use storage::ecvrf::VRFKeyStorage;
pub use verify::{
    HistoryVerificationParams, history::HistoryParams, key_history_verify, lookup_verify,
};

// ========== Constants and type aliases ========== //
pub mod test_utils;
#[cfg(test)]
mod tests;

/// The length of a leaf node's label (in bits)
pub const LEAF_LEN: u32 = 256;

/// The label used for a root node
pub const ROOT_LABEL: crate::node_label::NodeLabel =
    crate::NodeLabel { label_val: [0u8; 32], label_len: 0 };
