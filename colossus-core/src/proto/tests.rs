//! Forked Code from Meta Platforms AKD repository: https://github.com/facebook/akd
//! Tests of the protobuf conversion logic

use super::specs::types::*;
use super::*;
use crate::akd::{AzksValue, Direction};
use rand::{Rng, rng};

// ================= Test helpers ================= //

fn random_hash() -> [u8; 32] {
    rng().random::<[u8; 32]>()
}

fn random_azks_element() -> crate::akd::AzksElement {
    crate::akd::AzksElement {
        label: random_label(),
        value: AzksValue(random_hash()),
    }
}

fn random_label() -> crate::akd::NodeLabel {
    let label = crate::akd::NodeLabel {
        label_val: random_hash(),
        label_len: rng().random::<u32>() % 257, // Can be up to 256
    };
    label.get_prefix(label.label_len)
}

fn membership_proof() -> crate::akd::proofs::MembershipProof {
    crate::akd::proofs::MembershipProof {
        label: random_label(),
        hash_val: AzksValue(random_hash()),
        sibling_proofs: vec![crate::akd::proofs::SiblingProof {
            label: random_label(),
            siblings: [random_azks_element()],
            direction: Direction::Right,
        }],
    }
}

// ================= Test cases ================= //

#[test]
fn test_convert_nodelabel() {
    let original = random_label();

    let protobuf: NodeLabel = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_azks_element() {
    let original = random_azks_element();

    let protobuf: AzksElement = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_layer_proof() {
    let original = crate::akd::proofs::SiblingProof {
        label: random_label(),
        siblings: [random_azks_element()],
        direction: Direction::Right,
    };

    let protobuf: SiblingProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_membership_proof() {
    let original = crate::akd::proofs::MembershipProof {
        label: random_label(),
        hash_val: AzksValue(random_hash()),
        sibling_proofs: vec![crate::akd::proofs::SiblingProof {
            label: random_label(),
            siblings: [random_azks_element()],
            direction: Direction::Right,
        }],
    };

    let protobuf: MembershipProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_non_membership_proof() {
    let original = crate::akd::proofs::NonMembershipProof {
        label: random_label(),
        longest_prefix: random_label(),
        longest_prefix_children: [random_azks_element(), random_azks_element()],
        longest_prefix_membership_proof: crate::akd::proofs::MembershipProof {
            label: random_label(),
            hash_val: AzksValue(random_hash()),
            sibling_proofs: vec![crate::akd::proofs::SiblingProof {
                label: random_label(),
                siblings: [random_azks_element()],
                direction: Direction::Right,
            }],
        },
    };

    let protobuf: NonMembershipProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_lookup_proof() {
    let mut rng = rng();
    let original = crate::akd::proofs::LookupProof {
        epoch: rng.random(),
        value: crate::akd::AkdValue(random_hash().to_vec()),
        version: rng.random(),
        existence_vrf_proof: random_hash().to_vec(),
        existence_proof: crate::akd::proofs::MembershipProof {
            label: random_label(),
            hash_val: AzksValue(random_hash()),
            sibling_proofs: vec![crate::akd::proofs::SiblingProof {
                label: random_label(),
                siblings: [random_azks_element()],
                direction: Direction::Right,
            }],
        },
        marker_vrf_proof: random_hash().to_vec(),
        marker_proof: crate::akd::proofs::MembershipProof {
            label: random_label(),
            hash_val: AzksValue(random_hash()),
            sibling_proofs: vec![crate::akd::proofs::SiblingProof {
                label: random_label(),
                siblings: [random_azks_element()],
                direction: Direction::Right,
            }],
        },
        freshness_vrf_proof: random_hash().to_vec(),
        freshness_proof: crate::akd::proofs::NonMembershipProof {
            label: random_label(),
            longest_prefix: random_label(),
            longest_prefix_children: [random_azks_element(), random_azks_element()],
            longest_prefix_membership_proof: crate::akd::proofs::MembershipProof {
                label: random_label(),
                hash_val: AzksValue(random_hash()),
                sibling_proofs: vec![crate::akd::proofs::SiblingProof {
                    label: random_label(),
                    siblings: [random_azks_element()],
                    direction: Direction::Right,
                }],
            },
        },
        commitment_nonce: random_hash().to_vec(),
    };

    let protobuf: LookupProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_update_proof() {
    let mut rng = rng();
    let original = crate::akd::proofs::UpdateProof {
        epoch: rng.random(),
        value: crate::akd::AkdValue(random_hash().to_vec()),
        version: rng.random(),
        existence_vrf_proof: random_hash().to_vec(),
        existence_proof: crate::akd::proofs::MembershipProof {
            label: random_label(),
            hash_val: AzksValue(random_hash()),
            sibling_proofs: vec![crate::akd::proofs::SiblingProof {
                label: random_label(),
                siblings: [random_azks_element()],
                direction: Direction::Right,
            }],
        },
        previous_version_vrf_proof: Some(random_hash().to_vec()),
        previous_version_proof: Some(crate::akd::proofs::MembershipProof {
            label: random_label(),
            hash_val: AzksValue(random_hash()),
            sibling_proofs: vec![crate::akd::proofs::SiblingProof {
                label: random_label(),
                siblings: [random_azks_element()],
                direction: Direction::Right,
            }],
        }),
        commitment_nonce: random_hash().to_vec(),
    };

    let protobuf: UpdateProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

fn non_membership_proof() -> crate::akd::proofs::NonMembershipProof {
    crate::akd::proofs::NonMembershipProof {
        label: random_label(),
        longest_prefix: random_label(),
        longest_prefix_children: [random_azks_element(), random_azks_element()],
        longest_prefix_membership_proof: crate::akd::proofs::MembershipProof {
            label: random_label(),
            hash_val: AzksValue(random_hash()),
            sibling_proofs: vec![crate::akd::proofs::SiblingProof {
                label: random_label(),
                siblings: [random_azks_element()],
                direction: Direction::Right,
            }],
        },
    }
}

fn upd_proof() -> crate::akd::proofs::UpdateProof {
    let mut rng = rng();
    crate::akd::proofs::UpdateProof {
        epoch: rng.random(),
        value: crate::akd::AkdValue(random_hash().to_vec()),
        version: rng.random(),
        existence_vrf_proof: random_hash().to_vec(),
        existence_proof: crate::akd::proofs::MembershipProof {
            label: random_label(),
            hash_val: AzksValue(random_hash()),
            sibling_proofs: vec![crate::akd::proofs::SiblingProof {
                label: random_label(),
                siblings: [random_azks_element()],
                direction: Direction::Right,
            }],
        },
        previous_version_vrf_proof: Some(random_hash().to_vec()),
        previous_version_proof: Some(crate::akd::proofs::MembershipProof {
            label: random_label(),
            hash_val: AzksValue(random_hash()),
            sibling_proofs: vec![crate::akd::proofs::SiblingProof {
                label: random_label(),
                siblings: [random_azks_element()],
                direction: Direction::Right,
            }],
        }),
        commitment_nonce: random_hash().to_vec(),
    }
}

#[test]
fn test_convert_history_proof() {
    let original = crate::akd::proofs::HistoryProof {
        update_proofs: vec![upd_proof(), upd_proof(), upd_proof()],
        past_marker_vrf_proofs: vec![
            random_hash().to_vec(),
            random_hash().to_vec(),
            random_hash().to_vec(),
        ],
        existence_of_past_marker_proofs: vec![
            membership_proof(),
            membership_proof(),
            membership_proof(),
        ],
        future_marker_vrf_proofs: vec![
            random_hash().to_vec(),
            random_hash().to_vec(),
            random_hash().to_vec(),
        ],
        non_existence_of_future_marker_proofs: vec![
            non_membership_proof(),
            non_membership_proof(),
            non_membership_proof(),
        ],
    };

    let protobuf: HistoryProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_convert_single_append_only_proof() {
    let inserted = [random_azks_element(), random_azks_element(), random_azks_element()];
    let unchanged_nodes = [
        random_azks_element(),
        random_azks_element(),
        random_azks_element(),
        random_azks_element(),
        random_azks_element(),
        random_azks_element(),
    ];
    let original = crate::akd::proofs::SingleAppendOnlyProof {
        inserted: inserted.to_vec(),
        unchanged_nodes: unchanged_nodes.to_vec(),
    };

    let protobuf: SingleAppendOnlyProof = (&original).into();
    assert_eq!(original, (&protobuf).try_into().unwrap());
}

#[test]
fn test_minimum_encoding_label_bytes() {
    let full_label: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

    let half_label: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    let zero_label: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    let min_full_label = encode_minimum_label(&full_label);
    let min_half_label = encode_minimum_label(&half_label);
    let min_zero_label = encode_minimum_label(&zero_label);

    assert_eq!(32, min_full_label.len());
    assert_eq!(16, min_half_label.len());
    assert_eq!(0, min_zero_label.len());

    assert_eq!(full_label, decode_minimized_label(&min_full_label));
    assert_eq!(half_label, decode_minimized_label(&min_half_label));
    assert_eq!(zero_label, decode_minimized_label(&min_zero_label));
}

#[test]
fn test_label_val_too_long() {
    let too_long_label: [u8; 33] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 1,
    ];

    let mut proto_label = specs::types::NodeLabel::new();
    proto_label.set_label_val(too_long_label.to_vec());
    proto_label.set_label_len(256);

    assert!(crate::akd::NodeLabel::try_from(&proto_label).is_err());
}

#[test]
fn test_label_len_too_large() {
    let full_label: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

    let mut proto_label = specs::types::NodeLabel::new();
    proto_label.set_label_val(full_label.to_vec());
    proto_label.set_label_len(257);

    assert!(crate::akd::NodeLabel::try_from(&proto_label).is_err());
}
