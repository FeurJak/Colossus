//! Forked Code from Meta Platforms AKD repository: https://github.com/facebook/akd
//! Errors for various data structure operations.
use core::fmt;

use crate::Direction;
use crate::node_label::NodeLabel;

/// A error related to verifiable random functions
#[derive(Debug, Eq, PartialEq)]
pub enum VrfError {
    /// A problem retrieving or decoding the VRF public key
    PublicKey(String),
    /// A problem retrieving or decoding the VRF signing key
    SigningKey(String),
    /// A problem verifying the VRF proof
    Verification(String),
}

impl core::fmt::Display for VrfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = match &self {
            VrfError::PublicKey(msg) => format!("(Public Key) - {msg}"),
            VrfError::SigningKey(msg) => format!("(Signing Key) - {msg}"),
            VrfError::Verification(msg) => format!("(Verification) - {msg}"),
        };
        write!(f, "Verifiable random function error {code}")
    }
}

/// Symbolizes a AkdError, thrown by the akd.
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum AkdError {
    /// Error propagation
    TreeNode(TreeNodeError),
    /// Error propagation
    Directory(DirectoryError),
    /// Error propagation
    AzksErr(AzksError),
    /// Vrf related error
    Vrf(VrfError),
    /// Storage layer error thrown
    Storage(StorageError),
    /// Audit verification error thrown
    AuditErr(AuditorError),
    /// Parallelism/concurrency related errors
    Parallelism(ParallelismError),
    /// Test error
    TestErr(String),
}

impl std::error::Error for AkdError {}

impl From<TreeNodeError> for AkdError {
    fn from(error: TreeNodeError) -> Self {
        Self::TreeNode(error)
    }
}

impl From<StorageError> for AkdError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<DirectoryError> for AkdError {
    fn from(error: DirectoryError) -> Self {
        Self::Directory(error)
    }
}

impl From<AzksError> for AkdError {
    fn from(error: AzksError) -> Self {
        Self::AzksErr(error)
    }
}

impl From<AuditorError> for AkdError {
    fn from(error: AuditorError) -> Self {
        Self::AuditErr(error)
    }
}

impl From<ParallelismError> for AkdError {
    fn from(error: ParallelismError) -> Self {
        Self::Parallelism(error)
    }
}

impl From<VerificationError> for AkdError {
    fn from(err: VerificationError) -> Self {
        Self::Directory(err.into())
    }
}

impl From<VrfError> for AkdError {
    fn from(error: VrfError) -> Self {
        Self::Vrf(error)
    }
}

impl std::fmt::Display for AkdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            AkdError::TreeNode(err) => {
                writeln!(f, "AKD Tree Node Error: {err}")
            },
            AkdError::Directory(err) => {
                writeln!(f, "AKD Directory Error: {err}")
            },
            AkdError::AzksErr(err) => {
                writeln!(f, "AKD AZKS Error: {err}")
            },
            AkdError::Vrf(err) => {
                writeln!(f, "AKD VRF Error: {err}")
            },
            AkdError::Storage(err) => {
                writeln!(f, "AKD Storage Error: {err}")
            },
            AkdError::AuditErr(err) => {
                writeln!(f, "AKD Auditor Error {err}")
            },
            AkdError::Parallelism(err) => {
                writeln!(f, "AKD Parallelism Error: {err}")
            },
            AkdError::TestErr(err) => {
                writeln!(f, "{err}")
            },
        }
    }
}

/// Errors thrown by TreeNodes
#[derive(Debug, Eq, PartialEq)]
pub enum TreeNodeError {
    /// At the moment the only supported dirs are 0, 1
    InvalidDirection(Direction),
    /// No direction provided for the node.
    /// Second parameter is the label of the child attempted to be set
    /// -- if there is one, otherwise it is None.
    NoDirection(NodeLabel, Option<NodeLabel>),
    /// The node didn't have a child in the given epoch
    NoChildAtEpoch(u64, Direction),
    /// The next epoch of this node's parent was invalid
    ParentNextEpochInvalid(u64),
    /// The hash of a parent was attempted to be updated, without setting the calling node as a child.
    HashUpdateOrderInconsistent,
    /// The node did not exist at epoch
    NonexistentAtEpoch(NodeLabel, u64),
    /// The state of a node did not exist at a given epoch
    NoStateAtEpoch(NodeLabel, u64),
    /// Failed to deserialize a digest
    DigestDeserializationFailed(String),
}

impl std::error::Error for TreeNodeError {}

impl fmt::Display for TreeNodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDirection(dir) => {
                write!(f, "AKD is based on a binary tree. No child with a given direction: {dir:?}")
            },
            Self::NoDirection(node_label, child_label) => {
                let mut to_print = format!("no direction provided for the node {node_label:?}");
                // Add child info if given.
                if let Some(child_label) = child_label {
                    let child_str = format!(" and child {child_label:?}");
                    to_print.push_str(&child_str);
                }
                write!(f, "{to_print}")
            },
            Self::NoChildAtEpoch(epoch, direction) => {
                write!(f, "no node in direction {direction:?} at epoch {epoch}")
            },
            Self::ParentNextEpochInvalid(epoch) => {
                write!(f, "Next epoch of parent is invalid, epoch = {epoch}")
            },
            Self::HashUpdateOrderInconsistent => {
                write!(f, "Hash update in parent only allowed after node is inserted")
            },
            Self::NonexistentAtEpoch(label, epoch) => {
                write!(f, "This node, labelled {label:?}, did not exist at epoch {epoch:?}.")
            },
            Self::NoStateAtEpoch(label, epoch) => {
                write!(f, "This node, labelled {label:?}, did not exist at epoch {epoch:?}.")
            },
            Self::DigestDeserializationFailed(inner_error) => {
                write!(f, "Encountered a serialization error {inner_error}")
            },
        }
    }
}

/// An error thrown by the Azks data structure.
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum AzksError {
    /// Membership proof did not verify
    VerifyMembershipProof(String),
    /// Append-only proof did not verify
    VerifyAppendOnlyProof,
    /// Thrown when a place where an epoch is needed wasn't provided one.
    NoEpochGiven,
}

impl std::error::Error for AzksError {}

impl fmt::Display for AzksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerifyMembershipProof(error_string) => {
                write!(f, "{error_string}")
            },
            Self::VerifyAppendOnlyProof => {
                write!(f, "Append only proof did not verify!")
            },
            Self::NoEpochGiven => {
                write!(f, "An epoch was required but not supplied")
            },
        }
    }
}

/// The errors thrown by various algorithms in [crate::directory::Directory]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum DirectoryError {
    /// A verification error occurred
    Verification(VerificationError),
    /// Tried to perform an operation on an invalid epoch or epoch range
    InvalidEpoch(String),
    /// AZKS not found in read-only directory mode
    ReadOnlyDirectory(String),
    /// Publish
    Publish(String),
    /// Detected an invalid version
    InvalidVersion(String),
}

impl std::error::Error for DirectoryError {}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verification(err) => {
                write!(f, "Verification failure {err}")
            },
            Self::InvalidEpoch(err_string) => {
                write!(f, "Invalid epoch {err_string}")
            },
            Self::ReadOnlyDirectory(inner_message) => {
                write!(f, "Directory in read-only mode: {inner_message}")
            },
            Self::Publish(inner_message) => {
                write!(f, "Directory publish error: {inner_message}")
            },
            Self::InvalidVersion(inner_message) => {
                write!(f, "Invalid version error: {inner_message}")
            },
        }
    }
}

impl From<VerificationError> for DirectoryError {
    fn from(err: VerificationError) -> Self {
        Self::Verification(err)
    }
}

/// Represents a storage-layer error
#[derive(Debug, PartialEq, Eq)]
pub enum StorageError {
    /// Data wasn't found in the storage layer
    NotFound(String),
    /// A transaction error
    Transaction(String),
    /// Some kind of storage connection error occurred
    Connection(String),
    /// Some other storage-layer error occurred
    Other(String),
}

impl std::error::Error for StorageError {}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Connection(inner) => {
                write!(f, "Storage connection: {inner}")
            },
            StorageError::Transaction(inner) => {
                write!(f, "Transaction: {inner}")
            },
            StorageError::NotFound(inner) => {
                write!(f, "Data not found: {inner}")
            },
            StorageError::Other(inner) => {
                write!(f, "Other storage error: {inner}")
            },
        }
    }
}

/// The errors thrown by various algorithms in [crate::directory::Directory]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum AuditorError {
    /// A general auditor error
    VerifyAuditProof(String),
}

impl std::error::Error for AuditorError {}

impl fmt::Display for AuditorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerifyAuditProof(err_string) => {
                write!(f, "Failed to verify audit {err_string}")
            },
        }
    }
}

/// The errors thrown by parallel code
#[cfg_attr(test, derive(PartialEq, Eq))]
#[derive(Debug)]
pub enum ParallelismError {
    /// A tokio task join error
    JoinErr(String),
}

impl std::error::Error for ParallelismError {}

impl fmt::Display for ParallelismError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JoinErr(err_string) => {
                write!(f, "Failed to join tokio task {err_string}")
            },
        }
    }
}

/// Proof verification error types
#[derive(Debug, Eq, PartialEq)]
pub enum VerificationError {
    /// Error verifying a membership proof
    MembershipProof(String),
    /// Error verifying a non-membership proof
    NonMembershipProof(String),
    /// Error verifying a lookup proof
    LookupProof(String),
    /// Error verifying a history proof
    HistoryProof(String),
    /// Error verifying a VRF proof
    Vrf(VrfError),
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = match &self {
            VerificationError::MembershipProof(err) => format!("(Membership proof) - {err}"),
            VerificationError::NonMembershipProof(err) => {
                format!("(Non-membership proof) - {err}")
            },
            VerificationError::LookupProof(err) => format!("(Lookup proof) - {err}"),
            VerificationError::HistoryProof(err) => format!("(History proof) - {err}"),
            VerificationError::Vrf(vrf) => vrf.to_string(),
        };
        write!(f, "Verification error {code}")
    }
}

impl From<VrfError> for VerificationError {
    fn from(input: VrfError) -> Self {
        VerificationError::Vrf(input)
    }
}
