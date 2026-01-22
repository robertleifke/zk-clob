use clob_core::input::{Message, Rules};
use clob_core::types::{Side, TimeInForce, U256};
use clob_core::verify::{batch_digest, domain_separator, message_hash, rules_hash};

#[test]
fn rules_hash_stable() {
    let rules = Rules {
        base_asset_id: [1u8; 32],
        quote_asset_id: [2u8; 32],
        price_scale: U256::from(1_000_000_000_000_000_000u128),
        tick_size: U256::from(1_000_000_000_000_000_000u128),
        lot_size: U256::from(1u64),
        taker_fee_bps: 10,
        maker_fee_bps: 0,
        max_orders_per_batch: 128,
        max_matches_per_order: 64,
        max_balance: U256::from(1_000_000u64),
    };
    let h1 = rules_hash(&rules);
    let h2 = rules_hash(&rules);
    assert_eq!(h1, h2);
}

#[test]
fn batch_digest_changes_with_order() {
    let domain = domain_separator(1, &[3u8; 32], &[4u8; 32]);
    let msg1 = Message::Cancel {
        trader: [9u8; 20],
        nonce: 1,
        order_id: [7u8; 32],
    };
    let msg2 = Message::Cancel {
        trader: [8u8; 20],
        nonce: 2,
        order_id: [6u8; 32],
    };
    let h1 = message_hash(&domain, &msg1);
    let h2 = message_hash(&domain, &msg2);
    let a = batch_digest(&domain, 1, &[h1, h2]);
    let b = batch_digest(&domain, 1, &[h2, h1]);
    assert_ne!(a, b);
}

#[test]
fn message_hash_distinct() {
    let domain = domain_separator(1, &[3u8; 32], &[4u8; 32]);
    let msg1 = Message::Place {
        trader: [9u8; 20],
        nonce: 1,
        order_id: [7u8; 32],
        side: Side::Buy,
        tif: TimeInForce::Gtc,
        tick_index: 1,
        qty_base: U256::from(1u64),
        prev_tick_hint: 0,
        next_tick_hint: 0,
    };
    let msg2 = Message::Place {
        trader: [9u8; 20],
        nonce: 1,
        order_id: [7u8; 32],
        side: Side::Sell,
        tif: TimeInForce::Gtc,
        tick_index: 1,
        qty_base: U256::from(1u64),
        prev_tick_hint: 0,
        next_tick_hint: 0,
    };
    let h1 = message_hash(&domain, &msg1);
    let h2 = message_hash(&domain, &msg2);
    assert_ne!(h1, h2);
}
