//! Forked Code from Meta Platforms AKD repository: https://github.com/facebook/akd
// 1. Create a hashmap of all prefixes of all elements of the node set
// 2. For each node in current_nodes set, check if each child is in prefix hashmap
// 3. If so, add child label to batch set

// Creates a byte array of 32 bytes from a u64
// Note that this representation is big-endian, and
// places the bits to the front of the output byte_array.
pub(crate) fn byte_arr_from_u64(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

#[allow(unused)]
pub(crate) fn random_label(rng: &mut impl rand::Rng) -> crate::NodeLabel {
    crate::NodeLabel { label_val: rng.random::<[u8; 32]>(), label_len: 256 }
}
