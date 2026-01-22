use alloc::vec::Vec;
use core::hash::{Hash, Hasher};

use hashbrown::HashMap;

use crate::constants::ZERO32;
use crate::errors::CoreError;
use crate::hash::keccak256;

#[derive(Clone, Debug)]
pub struct Proof {
    pub key: [u8; 32],
    pub value: Vec<u8>,
    pub present: bool,
    pub siblings: Vec<[u8; 32]>,
}

impl Proof {
    pub fn new(key: [u8; 32], value: Vec<u8>, present: bool, siblings: Vec<[u8; 32]>) -> Self {
        Self {
            key,
            value,
            present,
            siblings,
        }
    }
}

pub fn leaf_hash(key: &[u8; 32], value: &[u8]) -> [u8; 32] {
    let value_hash = keccak256(value);
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = 0x00;
    buf[1..33].copy_from_slice(key);
    buf[33..65].copy_from_slice(&value_hash);
    keccak256(&buf)
}

pub fn leaf_hash_absent() -> [u8; 32] {
    ZERO32
}

pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = 0x01;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    keccak256(&buf)
}

pub fn verify_proof(root: &[u8; 32], proof: &Proof) -> Result<[u8; 32], CoreError> {
    if proof.siblings.len() != 256 {
        return Err(CoreError::Invalid("invalid proof length"));
    }
    if !proof.present && !proof.value.is_empty() {
        return Err(CoreError::Invalid("absent proof has value bytes"));
    }
    let mut cur = if proof.present {
        leaf_hash(&proof.key, &proof.value)
    } else {
        leaf_hash_absent()
    };
    for depth in (0..256).rev() {
        let sibling = &proof.siblings[depth];
        let bit = get_bit(&proof.key, depth as u16);
        let (left, right) = if bit == 0 {
            (&cur, sibling)
        } else {
            (sibling, &cur)
        };
        cur = node_hash(left, right);
    }
    if &cur != root {
        return Err(CoreError::State("merkle proof root mismatch"));
    }
    Ok(cur)
}

#[cfg(feature = "debug_merkle")]
#[derive(Clone, Debug)]
pub struct ProofDebugInfo {
    pub leaf_hash: [u8; 32],
    pub computed_root: [u8; 32],
    pub first_mismatch_depth: Option<u16>,
}

#[cfg(feature = "debug_merkle")]
pub fn verify_proof_debug(root: &[u8; 32], proof: &Proof) -> Result<ProofDebugInfo, CoreError> {
    if proof.siblings.len() != 256 {
        return Err(CoreError::Invalid("invalid proof length"));
    }
    if !proof.present && !proof.value.is_empty() {
        return Err(CoreError::Invalid("absent proof has value bytes"));
    }
    let mut cur = if proof.present {
        leaf_hash(&proof.key, &proof.value)
    } else {
        leaf_hash_absent()
    };
    let leaf = cur;
    let mut first_mismatch_depth = None;
    for depth in (0..256).rev() {
        let sibling = &proof.siblings[depth];
        let bit = get_bit(&proof.key, depth as u16);
        let (left, right) = if bit == 0 {
            (&cur, sibling)
        } else {
            (sibling, &cur)
        };
        cur = node_hash(left, right);
        if first_mismatch_depth.is_none() {
            let mut tmp = cur;
            for depth2 in (0..depth).rev() {
                let sib2 = &proof.siblings[depth2];
                let bit2 = get_bit(&proof.key, depth2 as u16);
                let (l2, r2) = if bit2 == 0 {
                    (&tmp, sib2)
                } else {
                    (sib2, &tmp)
                };
                tmp = node_hash(l2, r2);
            }
            if &tmp != root {
                first_mismatch_depth = Some(depth as u16);
            }
        }
    }
    if &cur != root {
        return Err(CoreError::State("merkle proof root mismatch"));
    }
    Ok(ProofDebugInfo {
        leaf_hash: leaf,
        computed_root: cur,
        first_mismatch_depth,
    })
}

pub fn apply_proof(root: &[u8; 32], proof: &Proof, new_value: Option<Vec<u8>>) -> Result<[u8; 32], CoreError> {
    if proof.siblings.len() != 256 {
        return Err(CoreError::Invalid("invalid proof length"));
    }
    let old_root = verify_proof(root, proof)?;
    let new_leaf = match new_value.as_ref() {
        Some(bytes) => leaf_hash(&proof.key, bytes),
        None => leaf_hash_absent(),
    };
    let mut cur = new_leaf;
    for depth in (0..256).rev() {
        let sibling = &proof.siblings[depth];
        let bit = get_bit(&proof.key, depth as u16);
        let (left, right) = if bit == 0 {
            (&cur, sibling)
        } else {
            (sibling, &cur)
        };
        cur = node_hash(left, right);
    }
    if &old_root != root {
        return Err(CoreError::State("root changed during apply"));
    }
    Ok(cur)
}

pub fn get_bit(key: &[u8; 32], depth: u16) -> u8 {
    let byte_index = (depth / 8) as usize;
    let bit_index = 7 - (depth % 8);
    (key[byte_index] >> bit_index) & 1
}

#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    values: HashMap<[u8; 32], Vec<u8>>,
    empty_hashes: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Eq)]
struct NodeKey {
    depth: u16,
    prefix: [u8; 32],
}

impl PartialEq for NodeKey {
    fn eq(&self, other: &Self) -> bool {
        self.depth == other.depth && self.prefix == other.prefix
    }
}

impl Hash for NodeKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.depth.hash(state);
        self.prefix.hash(state);
    }
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        let mut empty_hashes = vec![[0u8; 32]; 257];
        empty_hashes[256] = ZERO32;
        for depth in (0..256).rev() {
            let child = empty_hashes[depth + 1];
            empty_hashes[depth] = node_hash(&child, &child);
        }
        Self {
            values: HashMap::new(),
            empty_hashes,
        }
    }

    pub fn root(&self) -> [u8; 32] {
        let mut memo = HashMap::new();
        compute_hash(
            &self.values,
            &self.empty_hashes,
            &mut memo,
            [0u8; 32],
            0,
        )
    }

    pub fn get(&self, key: [u8; 32]) -> Option<Vec<u8>> {
        self.values.get(&key).cloned()
    }

    pub fn update(&mut self, key: [u8; 32], value: Option<Vec<u8>>) {
        match value {
            Some(bytes) => {
                self.values.insert(key, bytes);
            }
            None => {
                self.values.remove(&key);
            }
        }
    }

    pub fn prove(&self, key: [u8; 32]) -> Proof {
        let mut memo = HashMap::new();
        let mut siblings = Vec::with_capacity(256);
        for depth in 0..256 {
            let bit = get_bit(&key, depth as u16);
            let prefix = prefix_with_len(&key, depth as u16);
            let sibling_prefix = extend_prefix(&prefix, depth as u16, bit ^ 1);
            let hash = compute_hash(
                &self.values,
                &self.empty_hashes,
                &mut memo,
                sibling_prefix,
                depth as u16 + 1,
            );
            siblings.push(hash);
        }
        let (value, present) = match self.values.get(&key) {
            Some(bytes) => (bytes.clone(), true),
            None => (Vec::new(), false),
        };
        Proof {
            key,
            value,
            present,
            siblings,
        }
    }
}

fn prefix_with_len(key: &[u8; 32], bits: u16) -> [u8; 32] {
    if bits == 0 {
        return [0u8; 32];
    }
    if bits >= 256 {
        return *key;
    }
    let mut out = *key;
    let byte_index = (bits / 8) as usize;
    let bit_index = (bits % 8) as u8;
    if bit_index == 0 {
        for i in byte_index..32 {
            out[i] = 0;
        }
        return out;
    }
    let mask = 0xFFu8 << (8 - bit_index);
    out[byte_index] &= mask;
    for i in (byte_index + 1)..32 {
        out[i] = 0;
    }
    out
}

fn extend_prefix(prefix: &[u8; 32], depth: u16, bit: u8) -> [u8; 32] {
    let mut out = prefix_with_len(prefix, depth);
    let byte_index = (depth / 8) as usize;
    let bit_index = 7 - (depth % 8);
    if bit == 1 {
        out[byte_index] |= 1 << bit_index;
    } else {
        out[byte_index] &= !(1 << bit_index);
    }
    out
}

fn compute_hash(
    values: &HashMap<[u8; 32], Vec<u8>>,
    empty_hashes: &[[u8; 32]],
    memo: &mut HashMap<NodeKey, [u8; 32]>,
    prefix: [u8; 32],
    depth: u16,
) -> [u8; 32] {
    let key = NodeKey { depth, prefix };
    if let Some(hash) = memo.get(&key) {
        return *hash;
    }
    let hash = if depth == 256 {
        match values.get(&prefix).map(Vec::as_slice) {
            Some(bytes) => leaf_hash(&prefix, bytes),
            None => leaf_hash_absent(),
        }
    } else {
        let left_prefix = extend_prefix(&prefix, depth, 0);
        let right_prefix = extend_prefix(&prefix, depth, 1);
        let left = if has_value(values, &left_prefix, depth + 1) {
            compute_hash(values, empty_hashes, memo, left_prefix, depth + 1)
        } else {
            empty_hashes[(depth + 1) as usize]
        };
        let right = if has_value(values, &right_prefix, depth + 1) {
            compute_hash(values, empty_hashes, memo, right_prefix, depth + 1)
        } else {
            empty_hashes[(depth + 1) as usize]
        };
        node_hash(&left, &right)
    };
    memo.insert(key, hash);
    hash
}

fn has_value(values: &HashMap<[u8; 32], Vec<u8>>, prefix: &[u8; 32], depth: u16) -> bool {
    for key in values.keys() {
        if prefix_matches(key, prefix, depth) {
            return true;
        }
    }
    false
}

fn prefix_matches(key: &[u8; 32], prefix: &[u8; 32], depth: u16) -> bool {
    if depth == 0 {
        return true;
    }
    if depth >= 256 {
        return key == prefix;
    }
    let bits = depth as usize;
    let full_bytes = bits / 8;
    let rem_bits = bits % 8;
    if full_bytes > 0 && key[..full_bytes] != prefix[..full_bytes] {
        return false;
    }
    if rem_bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem_bits);
    key[full_bytes] & mask == prefix[full_bytes] & mask
}
