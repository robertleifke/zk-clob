use alloc::vec::Vec;

use crate::constants::*;
use crate::errors::CoreError;
use crate::hash::keccak256;
use crate::merkle::{apply_proof, verify_proof, Proof};
use crate::types::{Balance, FeeVault, MarketBest, Order, OrderNode, TickNode, U256};

pub trait StateAccess {
    fn read_value(&mut self, key: [u8; 32]) -> Result<Option<Vec<u8>>, CoreError>;
    fn write_value(&mut self, key: [u8; 32], value: Option<Vec<u8>>) -> Result<(), CoreError>;
}

pub fn key_balance(account: &[u8; 20], asset: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 1 + 20 + 32);
    buf.extend_from_slice(&NS_BAL);
    buf.push(0x1f);
    buf.extend_from_slice(account);
    buf.extend_from_slice(asset);
    keccak256(&buf)
}

pub fn key_nonce(account: &[u8; 20]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 1 + 20);
    buf.extend_from_slice(&NS_NONCE);
    buf.push(0x1f);
    buf.extend_from_slice(account);
    keccak256(&buf)
}

pub fn key_order(order_id: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 1 + 32);
    buf.extend_from_slice(&NS_ORDER);
    buf.push(0x1f);
    buf.extend_from_slice(order_id);
    keccak256(&buf)
}

pub fn key_order_node(order_id: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 1 + 32);
    buf.extend_from_slice(&NS_ORDERNODE);
    buf.push(0x1f);
    buf.extend_from_slice(order_id);
    keccak256(&buf)
}

pub fn key_tick_node(market: &[u8; 32], side: u8, tick: i32) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 1 + 32 + 1 + 4);
    buf.extend_from_slice(&NS_TICKNODE);
    buf.push(0x1f);
    buf.extend_from_slice(market);
    buf.push(side);
    buf.extend_from_slice(&tick.to_be_bytes());
    keccak256(&buf)
}

pub fn key_market_best(market: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 1 + 32);
    buf.extend_from_slice(&NS_MARKETBEST);
    buf.push(0x1f);
    buf.extend_from_slice(market);
    keccak256(&buf)
}

pub fn key_fee_vault(asset: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + 1 + 32);
    buf.extend_from_slice(&NS_FEEVAULT);
    buf.push(0x1f);
    buf.extend_from_slice(asset);
    keccak256(&buf)
}

pub struct ProofState<'a> {
    pub root: [u8; 32],
    proofs: &'a mut Vec<Proof>,
    pub touched_keys: Vec<[u8; 32]>,
}

impl<'a> ProofState<'a> {
    pub fn new(root: [u8; 32], proofs: &'a mut Vec<Proof>) -> Self {
        Self {
            root,
            proofs,
            touched_keys: Vec::new(),
        }
    }

    fn next_proof(&mut self) -> Result<Proof, CoreError> {
        if self.proofs.is_empty() {
            return Err(CoreError::State("missing proof"));
        }
        Ok(self.proofs.remove(0))
    }

    pub fn remaining_proofs(&self) -> usize {
        self.proofs.len()
    }
}

impl<'a> StateAccess for ProofState<'a> {
    fn read_value(&mut self, key: [u8; 32]) -> Result<Option<Vec<u8>>, CoreError> {
        let proof = self.next_proof()?;
        if proof.key != key {
            return Err(CoreError::State("proof key mismatch"));
        }
        verify_proof(&self.root, &proof)?;
        self.touched_keys.push(key);
        if proof.present {
            Ok(Some(proof.value))
        } else {
            Ok(None)
        }
    }

    fn write_value(&mut self, key: [u8; 32], value: Option<Vec<u8>>) -> Result<(), CoreError> {
        let proof = self.next_proof()?;
        if proof.key != key {
            return Err(CoreError::State("proof key mismatch"));
        }
        let new_root = apply_proof(&self.root, &proof, value)?;
        self.root = new_root;
        self.touched_keys.push(key);
        Ok(())
    }
}

#[cfg(feature = "std")]
pub struct RecordingState {
    pub root: [u8; 32],
    pub proofs: Vec<Proof>,
    pub tree: crate::merkle::SparseMerkleTree,
}

#[cfg(feature = "std")]
impl RecordingState {
    pub fn new(tree: crate::merkle::SparseMerkleTree) -> Self {
        let root = tree.root();
        Self {
            root,
            proofs: Vec::new(),
            tree,
        }
    }
}

#[cfg(feature = "std")]
impl StateAccess for RecordingState {
    fn read_value(&mut self, key: [u8; 32]) -> Result<Option<Vec<u8>>, CoreError> {
        let proof = self.tree.prove(key);
        self.proofs.push(proof.clone());
        if let Err(err) = verify_proof(&self.root, &proof) {
            #[cfg(feature = "debug_merkle")]
            {
                use crate::merkle::verify_proof_debug;
                let info = verify_proof_debug(&self.root, &proof);
                panic!("merkle debug key={:?} info={:?} err={:?}", key, info, err);
            }
            #[cfg(not(feature = "debug_merkle"))]
            {
                return Err(err);
            }
        }
        if proof.present {
            Ok(Some(proof.value))
        } else {
            Ok(None)
        }
    }

    fn write_value(&mut self, key: [u8; 32], value: Option<Vec<u8>>) -> Result<(), CoreError> {
        let proof = self.tree.prove(key);
        self.proofs.push(proof.clone());
        self.tree.update(key, value);
        self.root = self.tree.root();
        Ok(())
    }
}

pub fn get_balance<S: StateAccess>(state: &mut S, account: &[u8; 20], asset: &[u8; 32]) -> Result<Balance, CoreError> {
    let key = key_balance(account, asset);
    let value = state.read_value(key)?;
    if value.is_none() {
        return Ok(Balance::empty());
    }
    Balance::decode(value.as_ref().unwrap())
}

pub fn set_balance<S: StateAccess>(state: &mut S, account: &[u8; 20], asset: &[u8; 32], balance: &Balance) -> Result<(), CoreError> {
    let key = key_balance(account, asset);
    state.write_value(key, Some(balance.encode().to_vec()))
}

pub fn get_nonce<S: StateAccess>(state: &mut S, account: &[u8; 20]) -> Result<u64, CoreError> {
    let key = key_nonce(account);
    let value = state.read_value(key)?;
    if value.is_none() {
        return Ok(0u64);
    }
    let value = value.unwrap();
    if value.len() != 8 {
        return Err(CoreError::Decode("invalid nonce length"));
    }
    Ok(u64::from_be_bytes(value.try_into().unwrap()))
}

pub fn set_nonce<S: StateAccess>(state: &mut S, account: &[u8; 20], nonce: u64) -> Result<(), CoreError> {
    let key = key_nonce(account);
    state.write_value(key, Some(nonce.to_be_bytes().to_vec()))
}

pub fn get_order<S: StateAccess>(state: &mut S, order_id: &[u8; 32]) -> Result<Option<Order>, CoreError> {
    let key = key_order(order_id);
    let value = state.read_value(key)?;
    if value.is_none() {
        return Ok(None);
    }
    Ok(Some(Order::decode(value.as_ref().unwrap())?))
}

pub fn set_order<S: StateAccess>(state: &mut S, order_id: &[u8; 32], order: &Order) -> Result<(), CoreError> {
    let key = key_order(order_id);
    state.write_value(key, Some(order.encode()))
}

pub fn get_order_node<S: StateAccess>(state: &mut S, order_id: &[u8; 32]) -> Result<OrderNode, CoreError> {
    let key = key_order_node(order_id);
    let value = state.read_value(key)?;
    if value.is_none() {
        return Ok(OrderNode {
            prev_order_id: NONE_ORDER_ID,
            next_order_id: NONE_ORDER_ID,
        });
    }
    OrderNode::decode(value.as_ref().unwrap())
}

pub fn set_order_node<S: StateAccess>(state: &mut S, order_id: &[u8; 32], node: &OrderNode) -> Result<(), CoreError> {
    let key = key_order_node(order_id);
    state.write_value(key, Some(node.encode().to_vec()))
}

pub fn get_tick_node<S: StateAccess>(state: &mut S, market: &[u8; 32], side: u8, tick: i32) -> Result<TickNode, CoreError> {
    let key = key_tick_node(market, side, tick);
    let value = state.read_value(key)?;
    if value.is_none() {
        return Ok(TickNode {
            prev_tick: NONE_TICK,
            next_tick: NONE_TICK,
            head_order_id: NONE_ORDER_ID,
            tail_order_id: NONE_ORDER_ID,
        });
    }
    TickNode::decode(value.as_ref().unwrap())
}

pub fn set_tick_node<S: StateAccess>(state: &mut S, market: &[u8; 32], side: u8, tick: i32, node: &TickNode) -> Result<(), CoreError> {
    let key = key_tick_node(market, side, tick);
    state.write_value(key, Some(node.encode().to_vec()))
}

pub fn get_market_best<S: StateAccess>(state: &mut S, market: &[u8; 32]) -> Result<MarketBest, CoreError> {
    let key = key_market_best(market);
    let value = state.read_value(key)?;
    if value.is_none() {
        return Ok(MarketBest {
            best_bid: NONE_TICK,
            best_ask: NONE_TICK,
        });
    }
    MarketBest::decode(value.as_ref().unwrap())
}

pub fn set_market_best<S: StateAccess>(state: &mut S, market: &[u8; 32], best: &MarketBest) -> Result<(), CoreError> {
    let key = key_market_best(market);
    state.write_value(key, Some(best.encode().to_vec()))
}

pub fn get_fee_vault<S: StateAccess>(state: &mut S, asset: &[u8; 32]) -> Result<FeeVault, CoreError> {
    let key = key_fee_vault(asset);
    let value = state.read_value(key)?;
    if value.is_none() {
        return Ok(FeeVault {
            total: U256::zero(),
        });
    }
    FeeVault::decode(value.as_ref().unwrap())
}

pub fn set_fee_vault<S: StateAccess>(state: &mut S, asset: &[u8; 32], fee: &FeeVault) -> Result<(), CoreError> {
    let key = key_fee_vault(asset);
    state.write_value(key, Some(fee.encode().to_vec()))
}
