use alloc::vec::Vec;

use crate::constants::ZERO32;
use crate::hash::keccak256;

pub fn merkle_root(leaves: &[ [u8; 32] ]) -> [u8; 32] {
    if leaves.is_empty() {
        return ZERO32;
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = if i + 1 < level.len() {
                level[i + 1]
            } else {
                level[i]
            };
            let mut buf = [0u8; 65];
            buf[0] = 0x01;
            buf[1..33].copy_from_slice(&left);
            buf[33..65].copy_from_slice(&right);
            next.push(keccak256(&buf));
            i += 2;
        }
        level = next;
    }
    level[0]
}
