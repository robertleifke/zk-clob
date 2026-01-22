use alloc::vec::Vec;

use crate::encoding::{Reader, Writer};
use crate::errors::CoreError;
use crate::merkle::Proof;
use crate::types::{Side, TimeInForce, U256};

#[derive(Clone, Debug)]
pub struct Rules {
    pub base_asset_id: [u8; 32],
    pub quote_asset_id: [u8; 32],
    pub price_scale: U256,
    pub tick_size: U256,
    pub lot_size: U256,
    pub taker_fee_bps: u32,
    pub maker_fee_bps: u32,
    pub max_orders_per_batch: u32,
    pub max_matches_per_order: u32,
    pub max_balance: U256,
}

impl Rules {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_b32(&self.base_asset_id);
        w.write_b32(&self.quote_asset_id);
        w.write_u256(&self.price_scale);
        w.write_u256(&self.tick_size);
        w.write_u256(&self.lot_size);
        w.write_u32(self.taker_fee_bps);
        w.write_u32(self.maker_fee_bps);
        w.write_u32(self.max_orders_per_batch);
        w.write_u32(self.max_matches_per_order);
        w.write_u256(&self.max_balance);
        w.into_bytes()
    }

    pub fn decode(reader: &mut Reader) -> Result<Self, CoreError> {
        Ok(Self {
            base_asset_id: reader.read_b32()?,
            quote_asset_id: reader.read_b32()?,
            price_scale: reader.read_u256()?,
            tick_size: reader.read_u256()?,
            lot_size: reader.read_u256()?,
            taker_fee_bps: reader.read_u32()?,
            maker_fee_bps: reader.read_u32()?,
            max_orders_per_batch: reader.read_u32()?,
            max_matches_per_order: reader.read_u32()?,
            max_balance: reader.read_u256()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PublicInputsPartial {
    pub prev_root: [u8; 32],
    pub batch_digest: [u8; 32],
    pub rules_hash: [u8; 32],
    pub domain_separator: [u8; 32],
    pub batch_seq: u64,
    pub batch_timestamp: u64,
    pub da_commitment: [u8; 32],
}

impl PublicInputsPartial {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_b32(&self.prev_root);
        w.write_b32(&self.batch_digest);
        w.write_b32(&self.rules_hash);
        w.write_b32(&self.domain_separator);
        w.write_u64(self.batch_seq);
        w.write_u64(self.batch_timestamp);
        w.write_b32(&self.da_commitment);
        w.into_bytes()
    }

    pub fn decode(reader: &mut Reader) -> Result<Self, CoreError> {
        Ok(Self {
            prev_root: reader.read_b32()?,
            batch_digest: reader.read_b32()?,
            rules_hash: reader.read_b32()?,
            domain_separator: reader.read_b32()?,
            batch_seq: reader.read_u64()?,
            batch_timestamp: reader.read_u64()?,
            da_commitment: reader.read_b32()?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub prev_root: [u8; 32],
    pub new_root: [u8; 32],
    pub batch_digest: [u8; 32],
    pub rules_hash: [u8; 32],
    pub domain_separator: [u8; 32],
    pub batch_seq: u64,
    pub batch_timestamp: u64,
    pub da_commitment: [u8; 32],
    pub trades_root: [u8; 32],
    pub fees_root: [u8; 32],
}

impl PublicInputs {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_b32(&self.prev_root);
        w.write_b32(&self.new_root);
        w.write_b32(&self.batch_digest);
        w.write_b32(&self.rules_hash);
        w.write_b32(&self.domain_separator);
        w.write_u64(self.batch_seq);
        w.write_u64(self.batch_timestamp);
        w.write_b32(&self.da_commitment);
        w.write_b32(&self.trades_root);
        w.write_b32(&self.fees_root);
        w.into_bytes()
    }
}

#[derive(Clone, Debug)]
pub struct MessageSignature {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

impl MessageSignature {
    pub fn encode(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = self.v;
        out
    }
}

#[derive(Clone, Debug)]
pub enum Message {
    Place {
        trader: [u8; 20],
        nonce: u64,
        order_id: [u8; 32],
        side: Side,
        tif: TimeInForce,
        tick_index: i32,
        qty_base: U256,
        prev_tick_hint: i32,
        next_tick_hint: i32,
    },
    Cancel {
        trader: [u8; 20],
        nonce: u64,
        order_id: [u8; 32],
    },
}

impl Message {
    pub fn type_id(&self) -> u8 {
        match self {
            Message::Place { .. } => 0x01,
            Message::Cancel { .. } => 0x02,
        }
    }

    pub fn encode_signed(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u8(self.type_id());
        match self {
            Message::Place {
                trader,
                nonce,
                order_id,
                side,
                tif,
                tick_index,
                qty_base,
                ..
            } => {
                w.write_addr(trader);
                w.write_u64(*nonce);
                w.write_b32(order_id);
                w.write_u8(side.as_u8());
                w.write_u32(tif.as_u32());
                w.write_i32(*tick_index);
                w.write_u256(qty_base);
            }
            Message::Cancel {
                trader, nonce, order_id, ..
            } => {
                w.write_addr(trader);
                w.write_u64(*nonce);
                w.write_b32(order_id);
            }
        }
        w.into_bytes()
    }
}

#[derive(Clone, Debug)]
pub struct SignedMessage {
    pub message: Message,
    pub signature: MessageSignature,
}

#[derive(Clone, Debug)]
pub struct GuestInput {
    pub public: PublicInputsPartial,
    pub chain_id: u64,
    pub venue_id: [u8; 32],
    pub market_id: [u8; 32],
    pub rules: Rules,
    pub messages: Vec<SignedMessage>,
}

impl GuestInput {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_raw(&self.public.encode());
        w.write_u64(self.chain_id);
        w.write_b32(&self.venue_id);
        w.write_b32(&self.market_id);
        w.write_raw(&self.rules.encode());
        w.write_u32(self.messages.len() as u32);
        for msg in &self.messages {
            match &msg.message {
                Message::Place {
                    trader,
                    nonce,
                    order_id,
                    side,
                    tif,
                    tick_index,
                    qty_base,
                    prev_tick_hint,
                    next_tick_hint,
                } => {
                    w.write_u8(0x01);
                    w.write_addr(trader);
                    w.write_u64(*nonce);
                    w.write_b32(order_id);
                    w.write_u8(side.as_u8());
                    w.write_u32(tif.as_u32());
                    w.write_i32(*tick_index);
                    w.write_u256(qty_base);
                    let sig = msg.signature.encode();
                    w.write_raw(&sig);
                    w.write_i32(*prev_tick_hint);
                    w.write_i32(*next_tick_hint);
                }
                Message::Cancel {
                    trader,
                    nonce,
                    order_id,
                } => {
                    w.write_u8(0x02);
                    w.write_addr(trader);
                    w.write_u64(*nonce);
                    w.write_b32(order_id);
                    let sig = msg.signature.encode();
                    w.write_raw(&sig);
                }
            }
        }
        w.into_bytes()
    }

    pub fn decode(reader: &mut Reader) -> Result<Self, CoreError> {
        let public = PublicInputsPartial::decode(reader)?;
        let chain_id = reader.read_u64()?;
        let venue_id = reader.read_b32()?;
        let market_id = reader.read_b32()?;
        let rules = Rules::decode(reader)?;
        let msg_count = reader.read_u32()? as usize;
        let mut messages = Vec::with_capacity(msg_count);
        for _ in 0..msg_count {
            let msg_type = reader.read_u8()?;
            match msg_type {
                0x01 => {
                    let trader = reader.read_addr()?;
                    let nonce = reader.read_u64()?;
                    let order_id = reader.read_b32()?;
                    let side = Side::from_u8(reader.read_u8()?)?;
                    let tif = TimeInForce::from_u32(reader.read_u32()?)?;
                    let tick_index = reader.read_i32()?;
                    let qty_base = reader.read_u256()?;
                    let sig_bytes = reader.read_exact(65)?;
                    let signature = MessageSignature {
                        r: sig_bytes[..32].try_into().unwrap(),
                        s: sig_bytes[32..64].try_into().unwrap(),
                        v: sig_bytes[64],
                    };
                    let prev_tick_hint = reader.read_i32()?;
                    let next_tick_hint = reader.read_i32()?;
                    messages.push(SignedMessage {
                        message: Message::Place {
                            trader,
                            nonce,
                            order_id,
                            side,
                            tif,
                            tick_index,
                            qty_base,
                            prev_tick_hint,
                            next_tick_hint,
                        },
                        signature,
                    });
                }
                0x02 => {
                    let trader = reader.read_addr()?;
                    let nonce = reader.read_u64()?;
                    let order_id = reader.read_b32()?;
                    let sig_bytes = reader.read_exact(65)?;
                    let signature = MessageSignature {
                        r: sig_bytes[..32].try_into().unwrap(),
                        s: sig_bytes[32..64].try_into().unwrap(),
                        v: sig_bytes[64],
                    };
                    messages.push(SignedMessage {
                        message: Message::Cancel {
                            trader,
                            nonce,
                            order_id,
                        },
                        signature,
                    });
                }
                _ => return Err(CoreError::Decode("unknown message type")),
            }
        }
        Ok(Self {
            public,
            chain_id,
            venue_id,
            market_id,
            rules,
            messages,
        })
    }
}

#[derive(Clone, Debug)]
pub struct GuestBundle {
    pub input: GuestInput,
    pub proofs: Vec<Proof>,
}

impl GuestBundle {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_raw(&self.input.encode());
        w.write_u32(self.proofs.len() as u32);
        for proof in &self.proofs {
            w.write_b32(&proof.key);
            w.write_u8(if proof.present { 1 } else { 0 });
            w.write_bytes(&proof.value);
            if proof.siblings.len() != 256 {
                panic!("proof siblings length");
            }
            for sibling in &proof.siblings {
                w.write_b32(sibling);
            }
        }
        w.into_bytes()
    }

    pub fn decode(reader: &mut Reader) -> Result<Self, CoreError> {
        let input = GuestInput::decode(reader)?;
        let proof_count = reader.read_u32()? as usize;
        let mut proofs = Vec::with_capacity(proof_count);
        for _ in 0..proof_count {
            let key = reader.read_b32()?;
            let present = reader.read_u8()? != 0;
            let value = reader.read_bytes()?;
            let mut siblings = Vec::with_capacity(256);
            for _ in 0..256 {
                siblings.push(reader.read_b32()?);
            }
            proofs.push(Proof { key, value, present, siblings });
        }
        Ok(Self { input, proofs })
    }
}
