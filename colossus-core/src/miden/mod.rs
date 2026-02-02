//! Miden Integration Module
//!
//! This module provides types and utilities for integrating Colossus with Polygon Miden.
//! It defines note types that can be used for on-chain storage and verification of:
//!
//! - Capability tokens and their attestations
//! - Revocation registry commitments
//! - Authority delegation certificates
//! - Identity attestations
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     Miden Note Type Hierarchy                            │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐  │
//! │  │  CapabilityNote  │    │ RevocationNote   │    │ AttestationNote  │  │
//! │  │                  │    │                  │    │                  │  │
//! │  │ - token_commit   │    │ - smt_root       │    │ - authority_pk   │  │
//! │  │ - authority_pk   │    │ - timestamp      │    │ - subject_commit │  │
//! │  │ - rights_hash    │    │ - count          │    │ - timestamp      │  │
//! │  │ - expiry         │    │ - signature      │    │ - signature      │  │
//! │  └──────────────────┘    └──────────────────┘    └──────────────────┘  │
//! │           │                      │                       │              │
//! │           └──────────────────────┼───────────────────────┘              │
//! │                                  ▼                                       │
//! │                    ┌──────────────────────────┐                         │
//! │                    │    NoteMetadata          │                         │
//! │                    │                          │                         │
//! │                    │ - note_type: u8          │                         │
//! │                    │ - version: u8            │                         │
//! │                    │ - created_at: u64        │                         │
//! │                    │ - tag: Word              │                         │
//! │                    └──────────────────────────┘                         │
//! │                                  │                                       │
//! │                                  ▼                                       │
//! │                    ┌──────────────────────────┐                         │
//! │                    │    Miden Blockchain      │                         │
//! │                    │                          │                         │
//! │                    │ Notes stored as Words    │                         │
//! │                    │ Verifiable in STARK      │                         │
//! │                    └──────────────────────────┘                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Note Types
//!
//! All note types are designed to be:
//! - **Compact**: Fit within Miden's note size constraints
//! - **Verifiable**: Can be verified in STARK proofs using Poseidon2
//! - **Self-describing**: Include type tags and versions for forward compatibility
//!
//! # Usage
//!
//! ```
//! use colossus_core::miden::{NoteMetadata, NoteType};
//!
//! // Create note metadata
//! let metadata = NoteMetadata::new(
//!     NoteType::Capability,
//!     1000,  // timestamp
//! ).with_tag(42);
//!
//! // Convert to Word for on-chain storage
//! let word = metadata.to_word();
//! ```

pub mod notes;

pub use notes::{
    AttestationNote, CapabilityNote, DelegationNote, NoteMetadata, NoteType, RevocationNote,
};
