use clob_core::hash::keccak256;
use clob_core::merkle::{apply_proof, leaf_hash, leaf_hash_absent, verify_proof, SparseMerkleTree};

#[test]
fn merkle_roundtrip() {
    let mut tree = SparseMerkleTree::new();
    let key = keccak256(b"key-1");
    let value = b"hello".to_vec();
    tree.update(key, Some(value.clone()));

    let root = tree.root();
    let proof = tree.prove(key);
    verify_proof(&root, &proof).expect("verify proof");
    assert_eq!(proof.value, value);

    let new_value = b"world".to_vec();
    let new_root = apply_proof(&root, &proof, Some(new_value)).expect("apply proof");
    assert_ne!(root, new_root);
}

#[test]
fn proof_fails_on_wrong_root() {
    let mut tree = SparseMerkleTree::new();
    let key = keccak256(b"key-wrong-root");
    let value = b"value".to_vec();
    tree.update(key, Some(value));

    let root = tree.root();
    let proof = tree.prove(key);
    verify_proof(&root, &proof).expect("verify proof");

    let wrong_root = keccak256(b"not-the-root");
    let err = verify_proof(&wrong_root, &proof).expect_err("expected root mismatch");
    match err {
        clob_core::errors::CoreError::State(_) => {}
        _ => panic!("unexpected error type"),
    }
}

#[test]
fn merkle_two_keys() {
    let mut tree = SparseMerkleTree::new();
    let key1 = keccak256(b"key-a");
    let key2 = keccak256(b"key-b");
    tree.update(key1, Some(b"value-a".to_vec()));
    tree.update(key2, Some(b"value-b".to_vec()));

    let root = tree.root();
    let proof1 = tree.prove(key1);
    let proof2 = tree.prove(key2);

    verify_proof(&root, &proof1).expect("verify proof1");
    verify_proof(&root, &proof2).expect("verify proof2");
}

#[test]
fn leaf_hash_empty_is_keyed() {
    let key = keccak256(b"key-2");
    let empty_value = leaf_hash(&key, &[]);
    let absent = leaf_hash_absent();
    assert_ne!(empty_value, absent);
}
