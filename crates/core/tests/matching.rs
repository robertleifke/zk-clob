use clob_core::engine::apply_batch;
use clob_core::hash::keccak256;
use clob_core::input::{Message, MessageSignature, Rules, SignedMessage};
use clob_core::merkle::SparseMerkleTree;
use clob_core::state::{
    key_balance, key_market_best, key_nonce, key_order, key_order_node, key_tick_node, RecordingState,
};
use clob_core::types::{Balance, MarketBest, Order, OrderNode, OrderStatus, Side, TickNode, TimeInForce, U256};
use clob_core::verify::{domain_separator, message_hash};

use k256::ecdsa::SigningKey;

#[test]
fn single_fill_ioc_buy() {
    let base = [1u8; 32];
    let quote = [2u8; 32];
    let market = [3u8; 32];
    let rules = Rules {
        base_asset_id: base,
        quote_asset_id: quote,
        price_scale: U256::from(1_000_000_000_000_000_000u128),
        tick_size: U256::from(1_000_000_000_000_000_000u128),
        lot_size: U256::from(1u64),
        taker_fee_bps: 0,
        maker_fee_bps: 0,
        max_orders_per_batch: 128,
        max_matches_per_order: 64,
        max_balance: U256::from(1_000_000u64),
    };

    let maker_key = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
    let taker_key = SigningKey::from_slice(&[0x22u8; 32]).unwrap();
    let maker = addr_from_key(&maker_key);
    let taker = addr_from_key(&taker_key);

    let mut tree = SparseMerkleTree::new();
    let maker_balance = Balance {
        available: U256::zero(),
        locked: U256::from(10u64),
    };
    tree.update(key_balance(&maker, &base), Some(maker_balance.encode().to_vec()));
    tree.update(
        key_balance(&maker, &quote),
        Some(
            Balance {
                available: U256::zero(),
                locked: U256::zero(),
            }
            .encode()
            .to_vec(),
        ),
    );
    tree.update(
        key_balance(&taker, &quote),
        Some(
            Balance {
                available: U256::from(10u64),
                locked: U256::zero(),
            }
            .encode()
            .to_vec(),
        ),
    );
    tree.update(key_nonce(&taker), Some(0u64.to_be_bytes().to_vec()));

    let maker_order_id = keccak256(b"maker-order");
    let maker_order = Order {
        owner: maker,
        side: Side::Sell,
        tick: 1,
        qty_remaining: U256::from(10u64),
        tif: TimeInForce::Gtc,
        status: OrderStatus::Open,
    };
    tree.update(key_order(&maker_order_id), Some(maker_order.encode()));
    tree.update(
        key_order_node(&maker_order_id),
        Some(
            OrderNode {
                prev_order_id: [0u8; 32],
                next_order_id: [0u8; 32],
            }
            .encode()
            .to_vec(),
        ),
    );
    tree.update(
        key_tick_node(&market, Side::Sell.as_u8(), 1),
        Some(
            TickNode {
                prev_tick: i32::MIN,
                next_tick: i32::MIN,
                head_order_id: maker_order_id,
                tail_order_id: maker_order_id,
            }
            .encode()
            .to_vec(),
        ),
    );
    tree.update(
        key_market_best(&market),
        Some(
            MarketBest {
                best_bid: i32::MIN,
                best_ask: 1,
            }
            .encode()
            .to_vec(),
        ),
    );

    let domain = domain_separator(1, &[9u8; 32], &market);
    let taker_order_id = keccak256(b"taker-order");
    let message = Message::Place {
        trader: taker,
        nonce: 1,
        order_id: taker_order_id,
        side: Side::Buy,
        tif: TimeInForce::Ioc,
        tick_index: 1,
        qty_base: U256::from(5u64),
        prev_tick_hint: i32::MIN,
        next_tick_hint: i32::MIN,
    };
    let hash = message_hash(&domain, &message);
    let signature = sign_hash(&taker_key, hash);
    let signed = SignedMessage { message, signature };

    let mut state = RecordingState::new(tree);
    apply_batch(&mut state, market, &rules, domain, &[signed]).expect("apply batch");

    let maker_balance_after = Balance::decode(
        state
            .tree
            .get(key_balance(&maker, &base))
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    let maker_quote_after = Balance::decode(
        state
            .tree
            .get(key_balance(&maker, &quote))
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    let taker_quote_after = Balance::decode(
        state
            .tree
            .get(key_balance(&taker, &quote))
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    let taker_base_raw = state.tree.get(key_balance(&taker, &base));
    let taker_base_after = if let Some(bytes) = taker_base_raw {
        Balance::decode(&bytes).unwrap()
    } else {
        Balance::empty()
    };

    assert_eq!(maker_balance_after.locked, U256::from(5u64));
    assert_eq!(maker_quote_after.available, U256::from(5u64));
    assert_eq!(taker_quote_after.available, U256::from(5u64));
    assert_eq!(taker_base_after.available, U256::from(5u64));
}

fn addr_from_key(key: &SigningKey) -> [u8; 20] {
    let pubkey = key.verifying_key().to_encoded_point(false);
    let hash = keccak256(&pubkey.as_bytes()[1..]);
    hash[12..].try_into().unwrap()
}

fn sign_hash(key: &SigningKey, hash: [u8; 32]) -> MessageSignature {
    let (sig, recid) = key.sign_prehash_recoverable(&hash).expect("sign");
    let sig_bytes = sig.to_bytes();
    MessageSignature {
        r: sig_bytes[..32].try_into().unwrap(),
        s: sig_bytes[32..].try_into().unwrap(),
        v: recid.to_byte() + 27,
    }
}
