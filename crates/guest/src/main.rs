#![no_main]
sp1_zkvm::entrypoint!(main);

extern crate alloc;

use alloc::vec::Vec;

use clob_core::engine::apply_batch;
use clob_core::errors::CoreError;
use clob_core::hash::keccak256;
use clob_core::input::{GuestBundle, PublicInputs};
use clob_core::outputs::merkle_root;
use clob_core::state::ProofState;
use clob_core::verify::{batch_digest, domain_separator, rules_hash, message_hash};
use clob_core::types::FeeTotal;

pub fn main() {
    let input_bytes = sp1_zkvm::io::read::<Vec<u8>>();
    let mut reader = clob_core::encoding::Reader::new(&input_bytes);
    let bundle = GuestBundle::decode(&mut reader).expect("decode input");
    reader.expect_finished().expect("trailing bytes");

    let input = bundle.input;
    let mut proofs = bundle.proofs;

    let expected_domain = domain_separator(input.chain_id, &input.venue_id, &input.market_id);
    if expected_domain != input.public.domain_separator {
        panic!("domain separator mismatch");
    }
    let expected_rules = rules_hash(&input.rules);
    if expected_rules != input.public.rules_hash {
        panic!("rules hash mismatch");
    }

    let mut msg_hashes = Vec::with_capacity(input.messages.len());
    for msg in &input.messages {
        msg_hashes.push(message_hash(&expected_domain, &msg.message));
    }
    let expected_batch = batch_digest(&expected_domain, input.public.batch_seq, &msg_hashes);
    if expected_batch != input.public.batch_digest {
        panic!("batch digest mismatch");
    }

    let mut state = ProofState::new(input.public.prev_root, &mut proofs);
    let output = apply_batch(
        &mut state,
        input.market_id,
        &input.rules,
        expected_domain,
        &input.messages,
    )
    .unwrap_or_else(|e| panic!("apply batch failed: {e:?}"));

    if state.remaining_proofs() != 0 {
        panic!("unused proofs");
    }

    let trade_leaves: Vec<[u8; 32]> = output
        .trades
        .iter()
        .map(|t| keccak256(&t.encode()))
        .collect();
    let trades_root = merkle_root(&trade_leaves);

    let fee_leaves: Vec<[u8; 32]> = output
        .fee_totals
        .iter()
        .map(|f: &FeeTotal| keccak256(&f.encode()))
        .collect();
    let fees_root = merkle_root(&fee_leaves);

    let public = PublicInputs {
        prev_root: input.public.prev_root,
        new_root: state.root,
        batch_digest: input.public.batch_digest,
        rules_hash: input.public.rules_hash,
        domain_separator: input.public.domain_separator,
        batch_seq: input.public.batch_seq,
        batch_timestamp: input.public.batch_timestamp,
        da_commitment: input.public.da_commitment,
        trades_root,
        fees_root,
    };

    let mut touched_concat = Vec::with_capacity(state.touched_keys.len() * 32);
    for key in &state.touched_keys {
        touched_concat.extend_from_slice(key);
    }
    let touched_digest = keccak256(&touched_concat);

    sp1_zkvm::io::commit_slice(&public.encode());
    sp1_zkvm::io::write(&touched_digest);
}
