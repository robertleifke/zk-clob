pub const ZERO32: [u8; 32] = [0u8; 32];
pub const NONE_ORDER_ID: [u8; 32] = [0u8; 32];
pub const NONE_TICK: i32 = i32::MIN;

pub const NS_BAL: [u8; 32] = *b"NS_BAL__________________________";
pub const NS_NONCE: [u8; 32] = *b"NS_NONCE________________________";
pub const NS_ORDER: [u8; 32] = *b"NS_ORDER________________________";
pub const NS_ORDERNODE: [u8; 32] = *b"NS_ORDERNODE____________________";
pub const NS_TICKNODE: [u8; 32] = *b"NS_TICKNODE_____________________";
pub const NS_MARKETBEST: [u8; 32] = *b"NS_MARKETBEST___________________";
pub const NS_FEEVAULT: [u8; 32] = *b"NS_FEEVAULT_____________________";

pub const DOMAIN_TAG: &[u8] = b"NUMO_SPOT_CLOB_V1";
pub const BATCH_TAG: &[u8] = b"BATCH_V1";
