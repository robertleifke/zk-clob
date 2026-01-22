use std::fs;
use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

use clob_core::engine::apply_batch;
use clob_core::hash::keccak256;
use clob_core::input::{GuestBundle, GuestInput, Message, MessageSignature, PublicInputsPartial, Rules, SignedMessage};
use clob_core::merkle::SparseMerkleTree;
use clob_core::outputs::merkle_root;
use clob_core::state::RecordingState;
use clob_core::types::{FeeTotal, Side, TimeInForce, U256};
use clob_core::verify::{batch_digest, domain_separator, message_hash, rules_hash};

pub const CLOB_ELF: &[u8] = include_elf!("clob-guest");

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long, value_name = "FILE")]
    input: PathBuf,

    #[arg(long, value_name = "FILE")]
    output: PathBuf,
}

#[derive(Deserialize)]
struct InputFile {
    chain_id: u64,
    venue_id: String,
    market_id: String,
    rules: RulesJson,
    state: StateJson,
    batch: Vec<MessageJson>,
    batch_seq: u64,
    batch_timestamp: u64,
    da_commitment: String,
}

#[derive(Deserialize)]
struct RulesJson {
    base_asset_id: String,
    quote_asset_id: String,
    price_scale: String,
    tick_size: String,
    lot_size: String,
    taker_fee_bps: u32,
    maker_fee_bps: u32,
    max_orders_per_batch: u32,
    max_matches_per_order: u32,
    max_balance: String,
}

#[derive(Deserialize)]
struct StateJson {
    balances: Vec<BalanceJson>,
    nonces: Vec<NonceJson>,
    orders: Vec<OrderJson>,
    order_nodes: Vec<OrderNodeJson>,
    tick_nodes: Vec<TickNodeJson>,
    market_best: Option<MarketBestJson>,
    fee_vaults: Vec<FeeVaultJson>,
}

#[derive(Deserialize)]
struct BalanceJson {
    account: String,
    asset: String,
    available: String,
    locked: String,
}

#[derive(Deserialize)]
struct NonceJson {
    account: String,
    nonce: u64,
}

#[derive(Deserialize)]
struct OrderJson {
    order_id: String,
    owner: String,
    side: u8,
    tick: i32,
    qty_remaining: String,
    tif: u32,
    status: u8,
}

#[derive(Deserialize)]
struct OrderNodeJson {
    order_id: String,
    prev: String,
    next: String,
}

#[derive(Deserialize)]
struct TickNodeJson {
    side: u8,
    tick: i32,
    prev: i32,
    next: i32,
    head: String,
    tail: String,
}

#[derive(Deserialize)]
struct MarketBestJson {
    best_bid: i32,
    best_ask: i32,
}

#[derive(Deserialize)]
struct FeeVaultJson {
    asset: String,
    total: String,
}

#[derive(Deserialize)]
struct MessageJson {
    kind: String,
    trader: String,
    nonce: u64,
    order_id: String,
    side: Option<u8>,
    tif: Option<u32>,
    tick_index: Option<i32>,
    qty_base: Option<String>,
    prev_tick_hint: Option<i32>,
    next_tick_hint: Option<i32>,
    signature: String,
    private_key: Option<String>,
}

#[derive(Serialize)]
struct OutputFile {
    prev_root: String,
    new_root: String,
    batch_digest: String,
    rules_hash: String,
    domain_separator: String,
    trades_root: String,
    fees_root: String,
    public_values: String,
    proof: Option<String>,
}

fn main() {
    dotenv::dotenv().ok();
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Specify exactly one of --execute or --prove.");
        std::process::exit(1);
    }

    let input_text = fs::read_to_string(&args.input).expect("read input file");
    let input: InputFile = serde_json::from_str(&input_text).expect("parse input json");

    let rules = Rules {
        base_asset_id: parse_b32(&input.rules.base_asset_id),
        quote_asset_id: parse_b32(&input.rules.quote_asset_id),
        price_scale: parse_u256(&input.rules.price_scale),
        tick_size: parse_u256(&input.rules.tick_size),
        lot_size: parse_u256(&input.rules.lot_size),
        taker_fee_bps: input.rules.taker_fee_bps,
        maker_fee_bps: input.rules.maker_fee_bps,
        max_orders_per_batch: input.rules.max_orders_per_batch,
        max_matches_per_order: input.rules.max_matches_per_order,
        max_balance: parse_u256(&input.rules.max_balance),
    };

    let mut tree = SparseMerkleTree::new();
    populate_state(&mut tree, &input.state, &rules, parse_b32(&input.market_id));
    let prev_root = tree.root();

    let mut state = RecordingState::new(tree);
    let domain_sep = domain_separator(input.chain_id, &parse_b32(&input.venue_id), &parse_b32(&input.market_id));

    let messages = build_messages(&input.batch, &domain_sep);
    let output = apply_batch(&mut state, parse_b32(&input.market_id), &rules, domain_sep, &messages)
        .expect("apply batch");

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

    let rules_h = rules_hash(&rules);
    let mut msg_hashes = Vec::with_capacity(messages.len());
    for msg in &messages {
        msg_hashes.push(message_hash(&domain_sep, &msg.message));
    }
    let batch_d = batch_digest(&domain_sep, input.batch_seq, &msg_hashes);

    let guest_input = GuestInput {
        public: PublicInputsPartial {
            prev_root,
            batch_digest: batch_d,
            rules_hash: rules_h,
            domain_separator: domain_sep,
            batch_seq: input.batch_seq,
            batch_timestamp: input.batch_timestamp,
            da_commitment: parse_b32(&input.da_commitment),
        },
        chain_id: input.chain_id,
        venue_id: parse_b32(&input.venue_id),
        market_id: parse_b32(&input.market_id),
        rules,
        messages: messages.clone(),
    };
    let bundle = GuestBundle {
        input: guest_input,
        proofs: state.proofs.clone(),
    };

    let mut stdin = SP1Stdin::new();
    stdin.write(&bundle.encode());
    let client = ProverClient::from_env();

    let public_values;
    let proof_hex;

    if args.execute {
        let (output, _) = client.execute(CLOB_ELF, &stdin).run().expect("execute");
        public_values = hex::encode(output.as_slice());
        proof_hex = None;
    } else {
        let (pk, vk) = client.setup(CLOB_ELF);
        let proof = client.prove(&pk, &stdin).run().expect("prove");
        client.verify(&proof, &vk).expect("verify");
        public_values = hex::encode(proof.public_values.as_slice());
        proof_hex = Some(hex::encode(proof.proof.as_slice()));
    }

    let output_json = OutputFile {
        prev_root: format!("0x{}", hex::encode(prev_root)),
        new_root: format!("0x{}", hex::encode(state.root)),
        batch_digest: format!("0x{}", hex::encode(batch_d)),
        rules_hash: format!("0x{}", hex::encode(rules_h)),
        domain_separator: format!("0x{}", hex::encode(domain_sep)),
        trades_root: format!("0x{}", hex::encode(trades_root)),
        fees_root: format!("0x{}", hex::encode(fees_root)),
        public_values: format!("0x{}", public_values),
        proof: proof_hex.map(|p| format!("0x{}", p)),
    };

    fs::write(&args.output, serde_json::to_string_pretty(&output_json).unwrap())
        .expect("write output");
}

fn build_messages(batch: &[MessageJson], domain_sep: &[u8; 32]) -> Vec<SignedMessage> {
    batch
        .iter()
        .map(|msg| {
            let signature = if msg.signature == "auto" {
                let priv_key = msg.private_key.as_ref().expect("private_key");
                sign_message(priv_key, msg, domain_sep)
            } else {
                parse_sig(&msg.signature)
            };
            let trader = parse_addr(&msg.trader);
            match msg.kind.as_str() {
                "place" => SignedMessage {
                    message: Message::Place {
                        trader,
                        nonce: msg.nonce,
                        order_id: parse_b32(&msg.order_id),
                        side: Side::from_u8(msg.side.expect("side")).expect("side"),
                        tif: TimeInForce::from_u32(msg.tif.expect("tif")).expect("tif"),
                        tick_index: msg.tick_index.expect("tick_index"),
                        qty_base: parse_u256(msg.qty_base.as_ref().expect("qty_base")),
                        prev_tick_hint: msg.prev_tick_hint.unwrap_or(i32::MIN),
                        next_tick_hint: msg.next_tick_hint.unwrap_or(i32::MIN),
                    },
                    signature,
                },
                "cancel" => SignedMessage {
                    message: Message::Cancel {
                        trader,
                        nonce: msg.nonce,
                        order_id: parse_b32(&msg.order_id),
                    },
                    signature,
                },
                _ => panic!("unknown message kind"),
            }
        })
        .collect()
}

fn populate_state(tree: &mut SparseMerkleTree, state: &StateJson, rules: &Rules, market_id: [u8; 32]) {
    use clob_core::state::{
        key_balance, key_fee_vault, key_market_best, key_nonce, key_order, key_order_node,
        key_tick_node,
    };
    use clob_core::types::{Balance, FeeVault, MarketBest, Order, OrderNode, OrderStatus, TickNode};

    for bal in &state.balances {
        let key = key_balance(&parse_addr(&bal.account), &parse_b32(&bal.asset));
        let balance = Balance {
            available: parse_u256(&bal.available),
            locked: parse_u256(&bal.locked),
        };
        tree.update(key, Some(balance.encode().to_vec()));
    }
    for nonce in &state.nonces {
        let key = key_nonce(&parse_addr(&nonce.account));
        tree.update(key, Some(nonce.nonce.to_be_bytes().to_vec()));
    }
    for ord in &state.orders {
        let order = Order {
            owner: parse_addr(&ord.owner),
            side: Side::from_u8(ord.side).expect("side"),
            tick: ord.tick,
            qty_remaining: parse_u256(&ord.qty_remaining),
            tif: TimeInForce::from_u32(ord.tif).expect("tif"),
            status: OrderStatus::from_u8(ord.status).expect("status"),
        };
        let key = key_order(&parse_b32(&ord.order_id));
        tree.update(key, Some(order.encode()));
    }
    for node in &state.order_nodes {
        let key = key_order_node(&parse_b32(&node.order_id));
        let on = OrderNode {
            prev_order_id: parse_b32(&node.prev),
            next_order_id: parse_b32(&node.next),
        };
        tree.update(key, Some(on.encode().to_vec()));
    }
    for tick in &state.tick_nodes {
        let key = key_tick_node(&market_id, tick.side, tick.tick);
        let tn = TickNode {
            prev_tick: tick.prev,
            next_tick: tick.next,
            head_order_id: parse_b32(&tick.head),
            tail_order_id: parse_b32(&tick.tail),
        };
        tree.update(key, Some(tn.encode().to_vec()));
    }
    if let Some(best) = &state.market_best {
        let key = key_market_best(&market_id);
        let mb = MarketBest {
            best_bid: best.best_bid,
            best_ask: best.best_ask,
        };
        tree.update(key, Some(mb.encode().to_vec()));
    }
    for fee in &state.fee_vaults {
        let key = key_fee_vault(&parse_b32(&fee.asset));
        let fv = FeeVault {
            total: parse_u256(&fee.total),
        };
        tree.update(key, Some(fv.encode().to_vec()));
    }
    let _ = rules;
}

fn parse_b32(s: &str) -> [u8; 32] {
    let bytes = parse_hex(s);
    bytes.try_into().expect("b32 length")
}

fn parse_addr(s: &str) -> [u8; 20] {
    let bytes = parse_hex(s);
    bytes.try_into().expect("addr length")
}

fn parse_sig(s: &str) -> MessageSignature {
    let bytes = parse_hex(s);
    if bytes.len() != 65 {
        panic!("signature length");
    }
    MessageSignature {
        r: bytes[..32].try_into().unwrap(),
        s: bytes[32..64].try_into().unwrap(),
        v: bytes[64],
    }
}

fn sign_message(priv_key_hex: &str, msg: &MessageJson, domain_sep: &[u8; 32]) -> MessageSignature {
    use k256::ecdsa::SigningKey;
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let key_bytes = parse_hex(priv_key_hex);
    let signing_key = SigningKey::from_bytes(&key_bytes).expect("signing key");
    let trader = parse_addr(&msg.trader);
    let message = match msg.kind.as_str() {
        "place" => Message::Place {
            trader,
            nonce: msg.nonce,
            order_id: parse_b32(&msg.order_id),
            side: Side::from_u8(msg.side.expect("side")).expect("side"),
            tif: TimeInForce::from_u32(msg.tif.expect("tif")).expect("tif"),
            tick_index: msg.tick_index.expect("tick_index"),
            qty_base: parse_u256(msg.qty_base.as_ref().expect("qty_base")),
            prev_tick_hint: msg.prev_tick_hint.unwrap_or(i32::MIN),
            next_tick_hint: msg.next_tick_hint.unwrap_or(i32::MIN),
        },
        "cancel" => Message::Cancel {
            trader,
            nonce: msg.nonce,
            order_id: parse_b32(&msg.order_id),
        },
        _ => panic!("unknown message kind"),
    };
    let hash = message_hash(domain_sep, &message);
    let (sig, recid) = signing_key.sign_prehash_recoverable(&hash).expect("sign");
    let sig_bytes = sig.to_bytes();
    MessageSignature {
        r: sig_bytes[..32].try_into().unwrap(),
        s: sig_bytes[32..].try_into().unwrap(),
        v: recid.to_byte() + 27,
    }
}

fn parse_hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).expect("hex decode")
}

fn parse_u256(s: &str) -> U256 {
    let bytes = parse_hex(s);
    U256::from_be_bytes(&pad32(bytes))
}

fn pad32(mut bytes: Vec<u8>) -> [u8; 32] {
    if bytes.len() > 32 {
        panic!("u256 too long");
    }
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.append(&mut bytes);
        bytes = padded;
    }
    bytes.try_into().unwrap()
}
