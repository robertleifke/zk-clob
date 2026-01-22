use alloc::vec::Vec;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use crate::constants::{BATCH_TAG, DOMAIN_TAG};
use crate::errors::CoreError;
use crate::hash::keccak256;
use crate::input::{Message, MessageSignature, Rules};
use crate::types::U256;

pub fn domain_separator(chain_id: u64, venue_id: &[u8; 32], market_id: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(DOMAIN_TAG.len() + 8 + 32 + 32);
    buf.extend_from_slice(DOMAIN_TAG);
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(venue_id);
    buf.extend_from_slice(market_id);
    keccak256(&buf)
}

pub fn rules_hash(rules: &Rules) -> [u8; 32] {
    keccak256(&rules.encode())
}

pub fn message_hash(domain_separator: &[u8; 32], message: &Message) -> [u8; 32] {
    let msg_bytes = message.encode_signed();
    let msg_struct = keccak256(&msg_bytes);
    let mut buf = Vec::with_capacity(2 + 32 + 32);
    buf.push(0x19);
    buf.push(0x01);
    buf.extend_from_slice(domain_separator);
    buf.extend_from_slice(&msg_struct);
    keccak256(&buf)
}

pub fn batch_digest(
    domain_separator: &[u8; 32],
    batch_seq: u64,
    message_hashes: &[ [u8; 32] ],
) -> [u8; 32] {
    let mut msg_concat = Vec::with_capacity(message_hashes.len() * 32);
    for h in message_hashes {
        msg_concat.extend_from_slice(h);
    }
    let inner = keccak256(&msg_concat);
    let mut buf = Vec::with_capacity(BATCH_TAG.len() + 32 + 8 + 32);
    buf.extend_from_slice(BATCH_TAG);
    buf.extend_from_slice(domain_separator);
    buf.extend_from_slice(&batch_seq.to_be_bytes());
    buf.extend_from_slice(&inner);
    keccak256(&buf)
}

pub fn recover_address(hash: &[u8; 32], sig: &MessageSignature) -> Result<[u8; 20], CoreError> {
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.r);
    sig_bytes[32..].copy_from_slice(&sig.s);
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| CoreError::Signature("bad signature"))?;
    let v = match sig.v {
        0 | 1 => sig.v,
        27 | 28 => sig.v - 27,
        _ => return Err(CoreError::Signature("invalid v")),
    };
    let recovery_id = RecoveryId::from_byte(v).ok_or(CoreError::Signature("invalid recovery id"))?;
    let verify_key = VerifyingKey::recover_from_prehash(hash, &signature, recovery_id)
        .map_err(|_| CoreError::Signature("recover failed"))?;
    let pubkey = verify_key.to_encoded_point(false);
    let pubkey = pubkey.as_bytes();
    if pubkey.len() != 65 {
        return Err(CoreError::Signature("invalid pubkey"));
    }
    let addr = keccak256(&pubkey[1..]);
    Ok(addr[12..].try_into().unwrap())
}

pub fn verify_signature(
    domain_separator: &[u8; 32],
    message: &Message,
    sig: &MessageSignature,
    expected_addr: &[u8; 20],
) -> Result<(), CoreError> {
    let hash = message_hash(domain_separator, message);
    let addr = recover_address(&hash, sig)?;
    if &addr != expected_addr {
        return Err(CoreError::Signature("signer mismatch"));
    }
    Ok(())
}

pub fn price_from_tick(tick_index: i32, tick_size: U256) -> Result<U256, CoreError> {
    if tick_index < 0 {
        return Err(CoreError::Invalid("negative tick"));
    }
    let idx = U256::from(tick_index as u64);
    Ok(tick_size * idx)
}

pub fn check_tick_price_multiple(price: U256, tick_size: U256) -> Result<(), CoreError> {
    if tick_size.is_zero() {
        return Err(CoreError::Invalid("tick size zero"));
    }
    if (price % tick_size) != U256::zero() {
        return Err(CoreError::Invalid("price not tick multiple"));
    }
    Ok(())
}

pub fn check_lot_size(qty: U256, lot_size: U256) -> Result<(), CoreError> {
    if lot_size.is_zero() {
        return Err(CoreError::Invalid("lot size zero"));
    }
    if (qty % lot_size) != U256::zero() {
        return Err(CoreError::Invalid("qty not lot multiple"));
    }
    Ok(())
}
