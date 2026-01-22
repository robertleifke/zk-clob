use crate::encoding::Writer;
use crate::errors::CoreError;

use uint::construct_uint;

construct_uint! {
    pub struct U256(4);
}

construct_uint! {
    pub struct U512(8);
}

impl U256 {
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.to_big_endian(&mut out);
        out
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        U256::from_big_endian(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Buy,
    Sell,
}

impl Side {
    pub fn from_u8(value: u8) -> Result<Self, CoreError> {
        match value {
            0 => Ok(Side::Buy),
            1 => Ok(Side::Sell),
            _ => Err(CoreError::Decode("invalid side")),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Side::Buy => 0,
            Side::Sell => 1,
        }
    }

    pub fn opposite(self) -> Self {
        match self {
            Side::Buy => Side::Sell,
            Side::Sell => Side::Buy,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeInForce {
    Gtc,
    Ioc,
}

impl TimeInForce {
    pub fn from_u32(value: u32) -> Result<Self, CoreError> {
        match value {
            0 => Ok(TimeInForce::Gtc),
            1 => Ok(TimeInForce::Ioc),
            _ => Err(CoreError::Decode("invalid tif")),
        }
    }

    pub fn as_u32(self) -> u32 {
        match self {
            TimeInForce::Gtc => 0,
            TimeInForce::Ioc => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderStatus {
    Open,
    Filled,
    Canceled,
}

impl OrderStatus {
    pub fn from_u8(value: u8) -> Result<Self, CoreError> {
        match value {
            1 => Ok(OrderStatus::Open),
            2 => Ok(OrderStatus::Filled),
            3 => Ok(OrderStatus::Canceled),
            _ => Err(CoreError::Decode("invalid order status")),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            OrderStatus::Open => 1,
            OrderStatus::Filled => 2,
            OrderStatus::Canceled => 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Balance {
    pub available: U256,
    pub locked: U256,
}

impl Balance {
    pub fn empty() -> Self {
        Self {
            available: U256::zero(),
            locked: U256::zero(),
        }
    }

    pub fn encode(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.available.to_be_bytes());
        out[32..].copy_from_slice(&self.locked.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != 64 {
            return Err(CoreError::Decode("invalid balance length"));
        }
        Ok(Self {
            available: U256::from_be_bytes(&bytes[..32]),
            locked: U256::from_be_bytes(&bytes[32..]),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub owner: [u8; 20],
    pub side: Side,
    pub tick: i32,
    pub qty_remaining: U256,
    pub tif: TimeInForce,
    pub status: OrderStatus,
}

impl Order {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_addr(&self.owner);
        w.write_u8(self.side.as_u8());
        w.write_i32(self.tick);
        w.write_u256(&self.qty_remaining);
        w.write_u32(self.tif.as_u32());
        w.write_u8(self.status.as_u8());
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        let mut r = crate::encoding::Reader::new(bytes);
        let owner = r.read_addr()?;
        let side = Side::from_u8(r.read_u8()?)?;
        let tick = r.read_i32()?;
        let qty_remaining = r.read_u256()?;
        let tif = TimeInForce::from_u32(r.read_u32()?)?;
        let status = OrderStatus::from_u8(r.read_u8()?)?;
        r.expect_finished()?;
        Ok(Self {
            owner,
            side,
            tick,
            qty_remaining,
            tif,
            status,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderNode {
    pub prev_order_id: [u8; 32],
    pub next_order_id: [u8; 32],
}

impl OrderNode {
    pub fn encode(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.prev_order_id);
        out[32..].copy_from_slice(&self.next_order_id);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != 64 {
            return Err(CoreError::Decode("invalid order node length"));
        }
        Ok(Self {
            prev_order_id: bytes[..32].try_into().unwrap(),
            next_order_id: bytes[32..].try_into().unwrap(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TickNode {
    pub prev_tick: i32,
    pub next_tick: i32,
    pub head_order_id: [u8; 32],
    pub tail_order_id: [u8; 32],
}

impl TickNode {
    pub fn encode(&self) -> [u8; 72] {
        let mut out = [0u8; 72];
        out[..4].copy_from_slice(&self.prev_tick.to_be_bytes());
        out[4..8].copy_from_slice(&self.next_tick.to_be_bytes());
        out[8..40].copy_from_slice(&self.head_order_id);
        out[40..72].copy_from_slice(&self.tail_order_id);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != 72 {
            return Err(CoreError::Decode("invalid tick node length"));
        }
        Ok(Self {
            prev_tick: i32::from_be_bytes(bytes[..4].try_into().unwrap()),
            next_tick: i32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            head_order_id: bytes[8..40].try_into().unwrap(),
            tail_order_id: bytes[40..72].try_into().unwrap(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketBest {
    pub best_bid: i32,
    pub best_ask: i32,
}

impl MarketBest {
    pub fn encode(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self.best_bid.to_be_bytes());
        out[4..8].copy_from_slice(&self.best_ask.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != 8 {
            return Err(CoreError::Decode("invalid market best length"));
        }
        Ok(Self {
            best_bid: i32::from_be_bytes(bytes[..4].try_into().unwrap()),
            best_ask: i32::from_be_bytes(bytes[4..8].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeVault {
    pub total: U256,
}

impl FeeVault {
    pub fn encode(&self) -> [u8; 32] {
        self.total.to_be_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() != 32 {
            return Err(CoreError::Decode("invalid fee vault length"));
        }
        Ok(Self {
            total: U256::from_be_bytes(bytes),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TradeRecord {
    pub market_id: [u8; 32],
    pub maker_order_id: [u8; 32],
    pub taker_order_id: [u8; 32],
    pub maker: [u8; 20],
    pub taker: [u8; 20],
    pub side_taker: Side,
    pub maker_tick: i32,
    pub qty_base: U256,
    pub quote_amt: U256,
    pub taker_fee_quote: U256,
}

impl TradeRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_b32(&self.market_id);
        w.write_b32(&self.maker_order_id);
        w.write_b32(&self.taker_order_id);
        w.write_addr(&self.maker);
        w.write_addr(&self.taker);
        w.write_u8(self.side_taker.as_u8());
        w.write_i32(self.maker_tick);
        w.write_u256(&self.qty_base);
        w.write_u256(&self.quote_amt);
        w.write_u256(&self.taker_fee_quote);
        w.into_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeTotal {
    pub asset_id: [u8; 32],
    pub total_fee: U256,
}

impl FeeTotal {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_b32(&self.asset_id);
        w.write_u256(&self.total_fee);
        w.into_bytes()
    }
}
